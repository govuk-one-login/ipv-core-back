package uk.gov.di.ipv.core.reconcilemigratedvcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;
import uk.gov.di.ipv.core.library.factories.EvcsClientFactory;
import uk.gov.di.ipv.core.library.factories.ForkJoinPoolFactory;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.reconcilemigratedvcs.domain.ReconciliationReport;
import uk.gov.di.ipv.core.reconcilemigratedvcs.domain.Request;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_BATCH_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_STACK;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_HASH_USER_ID;

public class ReconcileMigratedVcsHandler implements RequestHandler<Request, ReconciliationReport> {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final int DEFAULT_PARALLELISM = 4;
    private static final int EVCS_CLIENT_GOAWAY_LIMIT = 9_000;
    private static final int TEN_SECS_IN_MS = 10_000;
    public static final int SIGNATURE_LENGTH = 87;

    private final ConfigService configService;
    private final EvcsClientFactory evcsClientFactory;
    private final ForkJoinPoolFactory forkJoinPoolFactory;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final Map<String, JWSVerifier> verifierMap = new HashMap<>();
    private final DataStore<VcStoreItem> tacticalDataStore;

    private ReconciliationReport reconciliationReport;
    private EvcsClient evcsClient;
    private int evcsClientCount;
    private int evcsCallCount;
    private ConcurrentSkipListSet<String> processedIdentities;
    private AtomicBoolean timeoutClose;

    public ReconcileMigratedVcsHandler(
            ConfigService configService,
            ForkJoinPoolFactory forkJoinPoolFactory,
            EvcsClientFactory evcsClientFactory,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            DataStore<VcStoreItem> tacticalDataStore) {
        this.configService = configService;
        this.forkJoinPoolFactory = forkJoinPoolFactory;
        this.evcsClientFactory = evcsClientFactory;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.tacticalDataStore = tacticalDataStore;
    }

    @ExcludeFromGeneratedCoverageReport
    public ReconcileMigratedVcsHandler() {
        configService = ConfigService.create();
        forkJoinPoolFactory = new ForkJoinPoolFactory();
        evcsClientFactory = new EvcsClientFactory(configService);
        gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        tacticalDataStore =
                DataStore.create(
                        EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME,
                        VcStoreItem.class,
                        configService);
    }

    @Override
    public ReconciliationReport handleRequest(Request request, Context context) {
        reconciliationReport = new ReconciliationReport(request);
        processedIdentities = new ConcurrentSkipListSet<>();
        var forkJoinPool =
                forkJoinPoolFactory.getForkJoinPool(
                        request.parallelism() == null
                                ? DEFAULT_PARALLELISM
                                : request.parallelism());
        timeoutClose = new AtomicBoolean(false);

        LOGGER.info(
                LogHelper.buildLogMessage("Starting reconciliation")
                        .with(LOG_BATCH_ID.getFieldName(), reconciliationReport.getBatchId())
                        .with("identities", request.userIds().size())
                        .with("parallelism", forkJoinPool.getParallelism()));

        evcsClient = evcsClientFactory.getClient();
        evcsClientCount = 1;
        evcsCallCount = 0;

        try {
            forkJoinPool
                    .submit(
                            () ->
                                    request.userIds().parallelStream()
                                            .unordered()
                                            .takeWhile(x -> !timeoutClose.get())
                                            .forEach(userId -> reconcileIdentity(userId, context)))
                    .get();
            var exitReason =
                    timeoutClose.get() ? "Lambda close to timeout" : "All identities processed";
            LOGGER.info(
                    LogHelper.buildLogMessage(exitReason)
                            .with(LOG_BATCH_ID.getFieldName(), reconciliationReport.getBatchId()));
            reconciliationReport.setExitReason(exitReason);
        } catch (InterruptedException | ExecutionException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOGGER.error(
                    LogHelper.buildErrorMessage("Parallel execution failed", e)
                            .with(LOG_BATCH_ID.getFieldName(), reconciliationReport.getBatchId())
                            .with(LOG_ERROR_STACK.getFieldName(), e.getStackTrace()));
            reconciliationReport.setExitReason("Parallel execution failed");
        } finally {
            forkJoinPool.shutdownNow();
            var unprocessedIdentities = new ArrayList<>(request.userIds());
            unprocessedIdentities.removeAll(processedIdentities);
            reconciliationReport.setUnprocessedHashedUserIds(
                    unprocessedIdentities.stream().map(DigestUtils::sha256Hex).toList());
            logReport();
        }

        return reconciliationReport;
    }

    private void reconcileIdentity(String userId, Context context) {
        var hashedUserId = DigestUtils.sha256Hex(userId);

        // Fetch VCs for user from EVCS
        List<String> evcsVcsStrings;
        try {
            evcsVcsStrings =
                    evcsClient.getUserVcsForMigrationReconciliation(userId).vcs().stream()
                            .map(EvcsGetUserVCDto::vc)
                            .sorted()
                            .toList();
            evcsCallCount++;
            refreshEvcsClientIfNeeded();
        } catch (Exception e) {
            logError("Error reading from EVCS", hashedUserId, e);
            reconciliationReport.incrementFailedEvcsRead(hashedUserId);
            reconciliationReport.incrementIdentitiesFullyProcessed();
            processedIdentities.add(userId);
            return;
        }

        // Fetch VCs from tactical
        List<String> tacticalVcsStrings;
        try {
            tacticalVcsStrings =
                    tacticalDataStore.getItems(userId).stream()
                            .map(VcStoreItem::getCredential)
                            .sorted()
                            .toList();
        } catch (Exception e) {
            logError("Error reading from tactical", hashedUserId, e);
            reconciliationReport.incrementFailedTacticalRead(hashedUserId);
            reconciliationReport.incrementIdentitiesFullyProcessed();
            processedIdentities.add(userId);
            return;
        }

        // Compare VCs
        if (!evcsVcsStrings.equals(tacticalVcsStrings)) {
            logVcDifferences(evcsVcsStrings, tacticalVcsStrings, hashedUserId);
            reconciliationReport.incrementDifferenceInVcs(hashedUserId);
            reconciliationReport.incrementIdentitiesFullyProcessed();
            processedIdentities.add(userId);
            return;
        } else {
            reconciliationReport.incrementVcsMatch();
        }

        if (reconciliationReport.isCheckSignatures() || reconciliationReport.isCheckP2()) {
            // Parse VCs from EVCS response
            List<VerifiableCredential> evcsVcs = new ArrayList<>();
            for (var vcString : evcsVcsStrings) {
                try {
                    var jwt = SignedJWT.parse(vcString);
                    var cri = configService.getCriByIssuer(jwt.getJWTClaimsSet().getIssuer());
                    evcsVcs.add(VerifiableCredential.fromValidJwt(userId, cri, jwt));
                } catch (ParseException | CredentialParseException | NoCriForIssuerException e) {
                    logError("Error parsing VC from EVCS", hashedUserId, e);
                    reconciliationReport.incrementFailedToParseEvcsVcs(hashedUserId);
                    reconciliationReport.incrementIdentitiesFullyProcessed();
                    processedIdentities.add(userId);
                    return;
                }
            }

            if (reconciliationReport.isCheckSignatures()) {
                // Validate VC signatures
                checkSignatures(evcsVcs, hashedUserId);
            }

            if (reconciliationReport.isCheckP2()) {
                // Check we've still got a P2 identity
                checkIfP2(evcsVcs, hashedUserId);
            }
        }

        processedIdentities.add(userId);
        reconciliationReport.incrementIdentitiesFullyProcessed();

        checkTimeout(context, hashedUserId);
    }

    private void checkSignatures(List<VerifiableCredential> evcsVcs, String hashedUserId) {
        var identityFailedSigValidation = false;
        for (var vc : evcsVcs) {
            try {
                if (!validSignature(vc, hashedUserId)) {
                    LOGGER.info(annotateLog("Failed to validate signature", hashedUserId));
                    reconciliationReport.incrementInvalidVcSignatureCount(hashedUserId, vc);
                    identityFailedSigValidation = true;
                }
            } catch (JOSEException | ParseException e) {
                logError("Error when validating signature", hashedUserId, e);
                reconciliationReport.incrementSignatureValidationErrorCount(hashedUserId, vc);
                identityFailedSigValidation = true;
            }
        }

        if (identityFailedSigValidation) {
            reconciliationReport.incrementIdentityWithInvalidSignatures(hashedUserId);
        } else {
            reconciliationReport.incrementIdentityWithValidSignatures();
        }
    }

    private void checkIfP2(List<VerifiableCredential> evcsVcs, String hashedUserId) {
        var matchedP2Profile =
                gpg45ProfileEvaluator.getFirstMatchingProfile(
                        gpg45ProfileEvaluator.buildScore(evcsVcs), List.of(M1A, M1B));
        if (matchedP2Profile.isEmpty()) {
            LOGGER.info(annotateLog("Failed to match a P2 profile", hashedUserId));
            reconciliationReport.incrementFailedToAttainP2(hashedUserId);
        } else {
            LOGGER.info(
                    annotateLog("Successfully matched P2 profile", hashedUserId)
                            .with("profile", matchedP2Profile.get().label));
            reconciliationReport.incrementSuccessfullyMatchedP2Count();
        }
    }

    private void checkTimeout(Context context, String hashUserId) {
        if (context.getRemainingTimeInMillis() <= TEN_SECS_IN_MS) {
            LOGGER.info(annotateLog("Lambda approaching timeout - shutting down", hashUserId));
            timeoutClose.set(true);
        }
    }

    private synchronized void refreshEvcsClientIfNeeded() {
        if (evcsCallCount / EVCS_CLIENT_GOAWAY_LIMIT == evcsClientCount) {
            // API gateway seems to have a limit on the number of requests from one
            // connection
            LOGGER.info(
                    LogHelper.buildLogMessage(
                                    "Approaching EVCS client GOAWAY limit, refreshing client")
                            .with("evcsClientCount", evcsClientCount)
                            .with("evcsCallCount", evcsCallCount));
            evcsClient = evcsClientFactory.getClient();
            evcsClientCount++;
        }
    }

    private boolean validSignature(VerifiableCredential vc, String hashedUserId)
            throws JOSEException, ParseException {
        // try all known keys until VC is validated, or return false
        for (var publicKey : configService.getHistoricSigningKeys(vc.getCri().getId())) {
            if (verifierMap.get(publicKey) == null) {
                try {
                    verifierMap.put(publicKey, new ECDSAVerifier(ECKey.parse(publicKey)));
                } catch (JOSEException | ParseException e) {
                    logError(
                            String.format("Error creating validator for %s", vc.getCri().getId()),
                            hashedUserId,
                            e);

                    throw e;
                }
            }
            SignedJWT formattedVc;
            try {
                formattedVc = transcodeSignatureIfDerFormat(vc.getSignedJwt());
            } catch (JOSEException | ParseException e) {
                logError("Error transcoding signature", hashedUserId, e);
                throw e;
            }
            if (formattedVc.verify(verifierMap.get(publicKey))) {
                return true;
            }
        }
        return false;
    }

    private SignedJWT transcodeSignatureIfDerFormat(SignedJWT verifiableCredential)
            throws JOSEException, ParseException {
        return signatureIsDerFormat(verifiableCredential)
                ? transcodeSignature(verifiableCredential)
                : verifiableCredential;
    }

    private SignedJWT transcodeSignature(SignedJWT vc) throws JOSEException, ParseException {
        LOGGER.info(LogHelper.buildLogMessage("Transcoding signature"));
        var transcodedSignatureBase64 =
                Base64URL.encode(
                        ECDSA.transcodeSignatureToConcat(
                                vc.getSignature().decode(),
                                ECDSA.getSignatureByteArrayLength(ES256)));

        var jwtParts = vc.getParsedParts();
        return new SignedJWT(jwtParts[0], jwtParts[1], transcodedSignatureBase64);
    }

    private boolean signatureIsDerFormat(SignedJWT signedJWT) throws JOSEException {
        return signedJWT.getSignature().decode().length != ECDSA.getSignatureByteArrayLength(ES256);
    }

    private void logError(String message, String hashedUserId, Throwable error) {
        LOGGER.error(
                annotateLog(message, hashedUserId)
                        .with(LOG_ERROR_DESCRIPTION.getFieldName(), error.getMessage())
                        .with(LOG_ERROR_STACK.getFieldName(), error.getStackTrace()));
    }

    private StringMapMessage annotateLog(String message, String hashedUserId) {
        return LogHelper.buildLogMessage(message)
                .with(LOG_HASH_USER_ID.getFieldName(), hashedUserId)
                .with(LOG_BATCH_ID.getFieldName(), reconciliationReport.getBatchId());
    }

    private void logVcDifferences(
            List<String> evcsVcsStrings, List<String> tacticalVcsStrings, String hashedUserId) {
        var evcsNotInTactical =
                evcsVcsStrings.stream()
                        .filter(evcsVc -> !tacticalVcsStrings.contains(evcsVc))
                        .toList();
        var tacticalNotInEvcs =
                tacticalVcsStrings.stream()
                        .filter(tacticalVc -> !evcsVcsStrings.contains(tacticalVc))
                        .toList();

        LOGGER.info(
                annotateLog("Difference in EVCS and tactical VCs", hashedUserId)
                        .with(
                                "evcsNotInTacticalSigs",
                                evcsNotInTactical.stream()
                                        .map(
                                                vc ->
                                                        vc.substring(
                                                                vc.length()
                                                                        - Math.min(
                                                                                vc.length(),
                                                                                SIGNATURE_LENGTH)))
                                        .toList())
                        .with(
                                "tacticalNotInEvcsSigs",
                                tacticalNotInEvcs.stream()
                                        .map(
                                                vc ->
                                                        vc.substring(
                                                                vc.length()
                                                                        - Math.min(
                                                                                vc.length(),
                                                                                SIGNATURE_LENGTH)))
                                        .toList()));
    }

    private void logReport() {
        try {
            LOGGER.info(
                    LogHelper.buildLogMessage("Returning report")
                            .with(
                                    "report",
                                    OBJECT_MAPPER.writeValueAsString(reconciliationReport)));
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to log report", e));
        }
    }
}
