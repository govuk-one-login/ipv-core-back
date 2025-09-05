package uk.gov.di.ipv.core.library.sis.service;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.audit.AuditExtensionsSisComparison;
import uk.gov.di.ipv.core.library.sis.audit.AuditRestrictedSisComparison;
import uk.gov.di.ipv.core.library.sis.client.SisClient;
import uk.gov.di.ipv.core.library.sis.client.SisGetStoredIdentityResult;
import uk.gov.di.ipv.core.library.sis.enums.FailureCode;
import uk.gov.di.ipv.core.library.sis.enums.VerificationOutcome;
import uk.gov.di.ipv.core.library.sis.exception.SisMatchException;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.model.ContraIndicator;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.domain.Cri.CIMIT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;

public class SisService {
    private final SisClient sisClient;
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final AuditService auditService;
    private final CimitUtilityService cimitUtilityService;
    private final UserIdentityService userIdentityService;
    private final VotMatcher votMatcher;
    private final EvcsService evcsService;
    private final CriResponseService criResponseService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    @ExcludeFromGeneratedCoverageReport
    public SisService(
            SisClient sisClient,
            ConfigService configService,
            AuditService auditService,
            CimitUtilityService cimitUtilityService,
            UserIdentityService userIdentityService,
            VotMatcher votMatcher,
            EvcsService evcsService,
            CriResponseService criResponseService) {
        this.sisClient = sisClient;
        this.configService = configService;
        this.auditService = auditService;
        this.cimitUtilityService = cimitUtilityService;
        this.userIdentityService = userIdentityService;
        this.votMatcher = votMatcher;
        this.evcsService = evcsService;
        this.criResponseService = criResponseService;
    }

    @ExcludeFromGeneratedCoverageReport
    public SisService(ConfigService configService) {
        this.configService = configService;
        this.sisClient = new SisClient(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.auditService = AuditService.create(configService);
        this.criResponseService = new CriResponseService(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.evcsService = new EvcsService(configService);
        this.votMatcher =
                new VotMatcher(
                        userIdentityService, new Gpg45ProfileEvaluator(), cimitUtilityService);
    }

    public SisGetStoredIdentityResult getStoredIdentity(
            ClientOAuthSessionItem clientOAuthSessionItem) {
        // We want to know what the strongest VOT is stored in SIS so we ask for all of them.
        return sisClient.getStoredIdentity(
                clientOAuthSessionItem.getEvcsAccessToken(),
                List.of(Vot.P0, Vot.P1, Vot.P2, Vot.P3),
                clientOAuthSessionItem.getGovukSigninJourneyId());
    }

    public void compareStoredIdentityWithStoredVcs(
            ClientOAuthSessionItem clientOAuthSessionItem, AuditEventUser auditEventUser) {
        SisGetStoredIdentityResult storedIdentityResult = null;
        List<String> sisVcSignatures = new ArrayList<>();
        List<String> evcsVcSignatures = new ArrayList<>();
        Optional<VotMatchingResult.VotAndProfile> maximumMatchedVot = Optional.empty();

        try {
            String evcsAccessToken = clientOAuthSessionItem.getEvcsAccessToken();
            String userId = clientOAuthSessionItem.getUserId();

            // Get SIS details
            storedIdentityResult = getStoredIdentity(clientOAuthSessionItem);

            if (!storedIdentityResult.requestSucceeded()) {
                throw new SisMatchException(
                        FailureCode.SIS_ERROR,
                        "Call to SIS service failed, no stored identity comparison can be made");
            }

            if (!storedIdentityResult.identityWasFound()) {
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "No credential found in SIS so no comparison to do"));
                return;
            }

            // Get stored signatures
            var storedJwtParts = storedIdentityResult.identityDetails().content().split("\\.");
            var storedJwt =
                    new SignedJWT(
                            new Base64URL(storedJwtParts[0]),
                            new Base64URL(storedJwtParts[1]),
                            new Base64URL(storedJwtParts[2]));
            var storedClaimset = storedJwt.getJWTClaimsSet();
            sisVcSignatures = (ArrayList<String>) storedClaimset.getClaims().get("credentials");

            // Get EVCS details
            var evcsCredentials = getEvcsVerifiableCredentials(userId, evcsAccessToken);

            evcsVcSignatures =
                    evcsCredentials.stream()
                            .map(credential -> getVcSignature(credential.getVcString()))
                            .toList();

            maximumMatchedVot = calculateMaximumMatchedVot(evcsCredentials, userId);

            // Compare VOTs
            var evcsVot = maximumMatchedVot.isPresent() ? maximumMatchedVot.get().vot() : null;
            if (storedIdentityResult.identityDetails().vot() != evcsVot) {
                throw new SisMatchException(
                        FailureCode.VOT_MISMATCH,
                        "EVCS ("
                                + (maximumMatchedVot.isPresent()
                                        ? maximumMatchedVot.get().vot()
                                        : "no VOT")
                                + ") and SIS ("
                                + storedIdentityResult.identityDetails().vot()
                                + ") vots do not match");
            }

            // Compare signatures
            var missingEvcsVcSignatures = new ArrayList<String>();
            var missingStoredSignatures = new ArrayList<String>();

            for (var evcsVcSignature : evcsVcSignatures) {
                if (!sisVcSignatures.contains(evcsVcSignature)) {
                    missingEvcsVcSignatures.add(evcsVcSignature);
                }
            }

            for (var storedSignature : sisVcSignatures) {
                if (!evcsVcSignatures.contains(storedSignature)) {
                    missingStoredSignatures.add(storedSignature);
                }
            }

            if (!missingEvcsVcSignatures.isEmpty()) {
                throw new SisMatchException(
                        FailureCode.MISSING_SIGNATURE,
                        "Some signatures from EVCS are not in the stored identity: "
                                + String.join(", ", missingEvcsVcSignatures));
            }

            if (!missingStoredSignatures.isEmpty()) {
                throw new SisMatchException(
                        FailureCode.EXTRA_SIGNATURE,
                        "Some signatures in the stored identity are not present in EVCS: "
                                + String.join(", ", missingStoredSignatures));
            }

            sendComparisonAuditEvent(
                    auditEventUser,
                    storedIdentityResult.identityDetails().vot(),
                    storedIdentityResult.identityDetails().isValid(),
                    storedIdentityResult.identityDetails().expired(),
                    VerificationOutcome.success,
                    null,
                    null,
                    evcsVcSignatures,
                    sisVcSignatures,
                    storedIdentityResult.identityDetails().content());
        } catch (SisMatchException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Comparison between SIS and EVCS failed", e));

            boolean sisIdFound = storedIdentityResult.identityWasFound();

            sendComparisonAuditEvent(
                    auditEventUser,
                    sisIdFound ? storedIdentityResult.identityDetails().vot() : null,
                    sisIdFound ? storedIdentityResult.identityDetails().isValid() : null,
                    sisIdFound ? storedIdentityResult.identityDetails().expired() : null,
                    VerificationOutcome.failure,
                    e.getFailureCode(),
                    e.getMessage(),
                    evcsVcSignatures,
                    sisVcSignatures,
                    sisIdFound ? storedIdentityResult.identityDetails().content() : "");
        } catch (Exception e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Unexpected error comparing SIS and EVCS identities", e));

            boolean sisIdFound = storedIdentityResult.identityWasFound();

            sendComparisonAuditEvent(
                    auditEventUser,
                    sisIdFound ? storedIdentityResult.identityDetails().vot() : null,
                    sisIdFound ? storedIdentityResult.identityDetails().isValid() : null,
                    sisIdFound ? storedIdentityResult.identityDetails().expired() : null,
                    VerificationOutcome.failure,
                    FailureCode.UNEXPECTED_ERROR,
                    e.getMessage(),
                    evcsVcSignatures,
                    sisVcSignatures,
                    sisIdFound ? storedIdentityResult.identityDetails().content() : "");
        }
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    private void sendComparisonAuditEvent(
            AuditEventUser auditEventUser,
            Vot sisVot,
            Boolean sisIsValid,
            Boolean sisIsExpired,
            VerificationOutcome verificationOutcome,
            FailureCode failureCode,
            String failureDetails,
            List<String> evcsSignatures,
            List<String> sisSignatures,
            String sisJwt) {

        try {
            var auditEvent =
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_STORED_IDENTITY_CHECKED,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            new AuditExtensionsSisComparison(
                                    sisVot,
                                    sisIsValid,
                                    sisIsExpired,
                                    verificationOutcome,
                                    failureCode),
                            new AuditRestrictedSisComparison(
                                    sisJwt, evcsSignatures, sisSignatures, failureDetails));
            auditService.sendAuditEvent(auditEvent);
        } catch (Exception e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Failed to send SIS comparison audit event", e));
        }
    }

    private String getVcSignature(String vcString) {
        var parts = vcString.split("\\.");
        return parts[2];
    }

    private Optional<VotMatchingResult.VotAndProfile> calculateMaximumMatchedVot(
            List<VerifiableCredential> evcsCredentials, String userId) throws SisMatchException {
        try {
            // Remove CIMIT VC from list of VCs, use it as security check credential
            List<ContraIndicator> contraIndicators = new ArrayList<>();
            var cimitVcList = evcsCredentials.stream().filter(vc -> vc.getCri() == CIMIT).toList();
            if (cimitVcList.size() != 1) {
                LOGGER.warn("Stored credentials do not contain exactly one CIMIT VC");
            } else {
                contraIndicators =
                        cimitUtilityService.getContraIndicatorsFromVc(
                                cimitVcList.getFirst().getVcString(), userId);
            }

            var vcsWithoutCimit =
                    evcsCredentials.stream().filter(vc -> !CIMIT.equals(vc.getCri())).toList();

            var areVcsCorrelated = userIdentityService.areVcsCorrelated(vcsWithoutCimit);

            // We don't care about matching any specific vot here, we just want to find out what the
            // highest vot is that can be matched.
            var votMatchingResult =
                    votMatcher.findStrongestMatches(
                            List.of(Vot.P0), vcsWithoutCimit, contraIndicators, areVcsCorrelated);

            return votMatchingResult.strongestMatch();
        } catch (Exception e) {
            throw new SisMatchException(
                    FailureCode.EVCS_VOT_CALCULATION_ERROR,
                    "Exception caught calculating VOT from EVCS VCs");
        }
    }

    private List<VerifiableCredential> getEvcsVerifiableCredentials(
            String userId, String evcsAccessToken) throws SisMatchException {
        try {
            var vcs =
                    evcsService.fetchEvcsVerifiableCredentialsByState(
                            userId, evcsAccessToken, true, CURRENT, PENDING_RETURN);

            // PENDING_RETURN vcs need a pending record to be valid
            var pendingRecords = criResponseService.getCriResponseItems(userId);
            var pendingReturnVcs = vcs.getOrDefault(PENDING_RETURN, List.of());
            var hasValidPendingReturnVcs =
                    !pendingRecords.isEmpty() && !isNullOrEmpty(pendingReturnVcs);

            var evcsIdentityVcs = new ArrayList<VerifiableCredential>();
            if (hasValidPendingReturnVcs) {
                // + pending return VCs
                evcsIdentityVcs.addAll(pendingReturnVcs);
            } else {
                // + all vcs
                evcsIdentityVcs.addAll(vcs.getOrDefault(CURRENT, List.of()));
            }

            return evcsIdentityVcs;
        } catch (Exception e) {
            throw new SisMatchException(
                    FailureCode.EVCS_ERROR, "Exception caught retrieving VCs from EVCS");
        }
    }
}
