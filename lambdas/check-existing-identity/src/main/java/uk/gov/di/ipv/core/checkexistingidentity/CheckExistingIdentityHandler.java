package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.checkexistingidentity.exceptions.MitigationRouteException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsEvcsMigration;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.enums.OperationalProfile;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EvcsMigrationService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.model.ContraIndicator;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.amazonaws.util.CollectionUtils.isNullOrEmpty;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BULK_MIGRATION_ROLLBACK_BATCHES;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REPEAT_FRAUD_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_WITH_STORE_PATH;

/** Check Existing Identity response Lambda */
public class CheckExistingIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_REUSE_WITH_STORE =
            new JourneyResponse(JOURNEY_REUSE_WITH_STORE_PATH);
    private static final JourneyResponse JOURNEY_OPERATIONAL_PROFILE_REUSE =
            new JourneyResponse(JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH);
    private static final JourneyResponse JOURNEY_IN_MIGRATION_REUSE =
            new JourneyResponse(JOURNEY_IN_MIGRATION_REUSE_PATH);
    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_LOW =
            new JourneyResponse(JOURNEY_IPV_GPG45_LOW_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_IPV_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL =
            new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_REPEAT_FRAUD_CHECK =
            new JourneyResponse(JOURNEY_REPEAT_FRAUD_CHECK_PATH);
    private static final JourneyResponse JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_REPROVE_IDENTITY_GPG45_LOW =
            new JourneyResponse(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH);

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CimitService cimitService;
    private final CimitUtilityService cimitUtilityService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final SessionCredentialsService sessionCredentialsService;
    private final EvcsService evcsService;
    private final EvcsMigrationService evcsMigrationService;

    @SuppressWarnings({
        "unused",
        "java:S107"
    }) // Used by AWS, methods should not have too many parameters
    public CheckExistingIdentityHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            CimitService cimitService,
            CimitUtilityService cimitUtilityService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService,
            EvcsService evcsService,
            EvcsMigrationService evcsMigrationService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.cimitService = cimitService;
        this.cimitUtilityService = cimitUtilityService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.evcsService = evcsService;
        this.evcsMigrationService = evcsMigrationService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler(ConfigService configService) {
        this.configService = ConfigService.create();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.auditService = AuditService.create(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.cimitService = new CimitService(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.evcsService = new EvcsService(configService);
        this.evcsMigrationService = new EvcsMigrationService(configService);
        VcHelper.setConfigService(this.configService);
    }

    private record VerifiableCredentialBundle(
            List<VerifiableCredential> credentials,
            boolean hasEvcsIdentity,
            boolean isPendingEvcsIdentity) {
        private boolean isF2fIdentity() {
            return credentials.stream().anyMatch(vc -> vc.getCri().equals(F2F));
        }
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            String ipvSessionId = getIpvSessionId(event);
            String ipAddress = getIpAddress(event);
            String deviceInformation = event.getDeviceInformation();
            configService.setFeatureSet(RequestHelper.getFeatureSet(event));

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSessionWithRetry(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            return getJourneyResponse(
                            ipvSessionItem, clientOAuthSessionItem, ipAddress, deviceInformation)
                    .toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_NOT_FOUND, ErrorResponse.IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    @SuppressWarnings({
        "java:S3776", // Cognitive Complexity of methods should not be too high
        "java:S6541" // "Brain method" PYIC-6901 should refactor this method
    })
    private JourneyResponse getJourneyResponse(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String ipAddress,
            String deviceInformation) {
        try {
            var ipvSessionId = ipvSessionItem.getIpvSessionId();
            var userId = clientOAuthSessionItem.getUserId();
            var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            var evcsAccessToken = clientOAuthSessionItem.getEvcsAccessToken();
            var vcs = getVerifiableCredentials(userId, evcsAccessToken);
            CriResponseItem f2fRequest = criResponseService.getFaceToFaceRequest(userId);
            final boolean hasF2fVc = vcs.isF2fIdentity();
            final boolean isF2FIncomplete = !Objects.isNull(f2fRequest) && !hasF2fVc;
            final boolean isF2FComplete =
                    !Objects.isNull(f2fRequest)
                            && hasF2fVc
                            && (!configService.enabled(EVCS_READ_ENABLED)
                                    || vcs.isPendingEvcsIdentity());

            // If we want to prove or mitigate CIs for an identity we want to go for the lowest
            // strength that is acceptable to the caller. We can only prove/mitigate GPG45
            // identities
            var lowestGpg45ConfidenceRequested =
                    clientOAuthSessionItem
                            .getParsedVtr()
                            .getLowestStrengthRequestedGpg45Vot(configService);

            // As almost all of our journeys are proving or mitigating a GPG45 vot we set the
            // target vot here as a default value. It will be overridden for identity reuse.
            ipvSessionItem.setTargetVot(lowestGpg45ConfidenceRequested);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            var contraIndicators =
                    cimitService.getContraIndicators(
                            clientOAuthSessionItem.getUserId(), govukSigninJourneyId, ipAddress);

            Optional<Boolean> reproveIdentity =
                    Optional.ofNullable(clientOAuthSessionItem.getReproveIdentity());

            if (reproveIdentity.orElse(false) || configService.enabled(RESET_IDENTITY)) {
                if (lowestGpg45ConfidenceRequested == Vot.P1) {
                    LOGGER.info(LogHelper.buildLogMessage("Resetting P1 identity"));
                    return JOURNEY_REPROVE_IDENTITY_GPG45_LOW;
                }

                LOGGER.info(LogHelper.buildLogMessage("Resetting P2 identity"));
                return JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM;
            }

            // PYIC-6901 Currently we just check against the lowest Vot requested for this journey.
            // That might cause an issue if a user needs to mitigate a P2 journey but comes back to
            // us with a P1 request that doesn't need mitigation. This is out of scope for the MVP
            // though.
            var ciScoringCheckResponse =
                    cimitUtilityService.getMitigationJourneyIfBreaching(
                            contraIndicators, lowestGpg45ConfidenceRequested);
            if (ciScoringCheckResponse.isPresent()) {
                return isF2FIncomplete
                        ? buildF2FIncompleteResponse(
                                f2fRequest) // F2F mitigation journey in progress
                        : ciScoringCheckResponse.get(); // CI fail or mitigation journey
            }

            // Check for credentials correlation failure
            var areGpg45VcsCorrelated = userIdentityService.areVcsCorrelated(vcs.credentials);

            var profileMatchResponse =
                    checkForProfileMatch(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            auditEventUser,
                            deviceInformation,
                            vcs,
                            areGpg45VcsCorrelated,
                            contraIndicators);
            if (profileMatchResponse.isPresent()) {
                // We are re-using an existing Vot so it might not be a GPG45 vot
                ipvSessionItem.setTargetVot(
                        clientOAuthSessionItem
                                .getParsedVtr()
                                .getLowestStrengthRequestedVot(configService));
                ipvSessionService.updateIpvSession(ipvSessionItem);
                return profileMatchResponse.get();
            }

            // No profile matched but has a pending F2F request
            if (isF2FIncomplete) {
                return buildF2FIncompleteResponse(f2fRequest);
            }

            // No profile match
            return isF2FComplete
                    ? buildF2FNoMatchResponse(
                            areGpg45VcsCorrelated,
                            auditEventUser,
                            deviceInformation,
                            contraIndicators)
                    : buildNoMatchResponse(contraIndicators, lowestGpg45ConfidenceRequested);
        } catch (HttpResponseExceptionWithErrorBody
                | VerifiableCredentialException
                | EvcsServiceException e) {
            return buildErrorResponse(e.getErrorResponse(), e);
        } catch (CiRetrievalException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_GET_STORED_CIS, e);
        } catch (ParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS, e);
        } catch (CredentialParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS, e);
        } catch (ConfigException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_CONFIG, e);
        } catch (UnrecognisedCiException e) {
            return buildErrorResponse(ErrorResponse.UNRECOGNISED_CI_CODE, e);
        } catch (MitigationRouteException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_FIND_MITIGATION_ROUTE, e);
        }
    }

    private VerifiableCredentialBundle getVerifiableCredentials(
            String userId, String evcsAccessToken)
            throws CredentialParseException, EvcsServiceException {

        var tacticalVcs = verifiableCredentialService.getVcs(userId);

        if (vcsAreFromEvcsMigrationRollbackBatch(tacticalVcs)) {
            tacticalVcs.forEach(vc -> vc.setBatchId(null));
            return new VerifiableCredentialBundle(tacticalVcs, false, false);
        }

        if (configService.enabled(EVCS_WRITE_ENABLED) || configService.enabled(EVCS_READ_ENABLED)) {
            var bundle = getEvcsCredentialBundle(userId, evcsAccessToken, tacticalVcs);
            if (bundle != null) {
                return bundle;
            }
        }

        return new VerifiableCredentialBundle(tacticalVcs, false, false);
    }

    private boolean vcsAreFromEvcsMigrationRollbackBatch(List<VerifiableCredential> tacticalVcs) {
        var batchIds =
                tacticalVcs.stream().map(VerifiableCredential::getBatchId).distinct().toList();
        if (batchIds.size() > 1) {
            LOGGER.warn(LogHelper.buildLogMessage("More than one batch ID found in tactical VCs"));
            return false;
        } else if (batchIds.isEmpty()
                || !new HashSet<>(
                                configService.getStringListParameter(
                                        BULK_MIGRATION_ROLLBACK_BATCHES))
                        .containsAll(batchIds)) {
            return false;
        }
        LOGGER.info(LogHelper.buildLogMessage("Previously migrated identity in rollback batch"));
        return true;
    }

    private VerifiableCredentialBundle getEvcsCredentialBundle(
            String userId, String evcsAccessToken, List<VerifiableCredential> tacticalVcs)
            throws CredentialParseException, EvcsServiceException {
        try {
            var evcsVcs =
                    evcsService.getVerifiableCredentialsByState(
                            userId, evcsAccessToken, CURRENT, PENDING_RETURN);

            // Use pending return vcs to determine identity if available
            var evcsIdentityVcs = evcsVcs.get(PENDING_RETURN);
            var isPendingEvcs = true;
            if (isNullOrEmpty(evcsIdentityVcs)) {
                evcsIdentityVcs = evcsVcs.get(CURRENT);
                isPendingEvcs = false;
            } else {
                // Ensure we keep any inherited ID VCs in the bundle
                evcsIdentityVcs.addAll(
                        evcsVcs.getOrDefault(CURRENT, List.of()).stream()
                                .filter(vc -> HMRC_MIGRATION.equals(vc.getCri()))
                                .toList());
            }

            // Check for partially migrated pending identity
            var hasPartiallyMigratedVcs =
                    hasPartiallyMigratedVcs(tacticalVcs, evcsIdentityVcs, isPendingEvcs);
            logIdentityMismatches(tacticalVcs, evcsVcs, hasPartiallyMigratedVcs);

            if (!isNullOrEmpty(evcsIdentityVcs)) {
                if (hasPartiallyMigratedVcs) {
                    // use tactical vcs but with evcs flags so that the store-identity lambda is
                    // called next and updates the evcs pending one
                    return new VerifiableCredentialBundle(tacticalVcs, true, true);
                } else {
                    return new VerifiableCredentialBundle(
                            configService.enabled(EVCS_READ_ENABLED)
                                    ? evcsIdentityVcs
                                    : tacticalVcs,
                            true,
                            isPendingEvcs);
                }
            }
        } catch (EvcsServiceException e) {
            if (configService.enabled(EVCS_READ_ENABLED)) {
                throw e;
            } else {
                LOGGER.error(LogHelper.buildErrorMessage("Failed to read EVCS VCs", e));
            }
        }
        return null;
    }

    private boolean hasPartiallyMigratedVcs(
            List<VerifiableCredential> tacticalVcs,
            List<VerifiableCredential> evcsVcs,
            boolean isPending) {

        if (!isPending) {
            return false;
        }

        // EVCS contains only a pending F2F VC
        if (evcsVcs.size() == 1 && F2F.equals(evcsVcs.get(0).getCri())) {
            return true;
        }

        // Tactical contains the same as pending EVCS, with one extra F2F VC
        if (tacticalVcs.size() == evcsVcs.size() + 1) {

            var extraF2fVcs =
                    tacticalVcs.stream()
                            .filter(
                                    credential ->
                                            F2F.equals(credential.getCri())
                                                    && evcsVcs.stream()
                                                            .noneMatch(
                                                                    evcsVC ->
                                                                            evcsVC.getVcString()
                                                                                    .equals(
                                                                                            credential
                                                                                                    .getVcString())))
                            .toList();

            return extraF2fVcs.size() == 1;
        }
        return false;
    }

    @ExcludeFromGeneratedCoverageReport
    private void logIdentityMismatches(
            List<VerifiableCredential> tacticalVcs,
            Map<EvcsVCState, List<VerifiableCredential>> evcsVcs,
            boolean hasPartiallyMigratedVcs) {

        if (hasPartiallyMigratedVcs) {
            LOGGER.info(LogHelper.buildLogMessage("found partially migrated vcs"));
            return;
        }
        var migratedTacticalVcStrings =
                tacticalVcs.stream()
                        .filter(vc -> vc.getMigrated() != null)
                        .map(VerifiableCredential::getVcString)
                        .collect(Collectors.toSet());

        // if we have pending vcs just check those
        var evcsToCheck =
                Optional.ofNullable(evcsVcs.get(PENDING_RETURN))
                        .or(() -> Optional.ofNullable(evcsVcs.get(CURRENT)))
                        .orElse(List.of());

        var allTacticalVcStrings =
                tacticalVcs.stream()
                        .map(VerifiableCredential::getVcString)
                        .collect(Collectors.toSet());

        var evcsVcStrings =
                evcsToCheck.stream()
                        .map(VerifiableCredential::getVcString)
                        .collect(Collectors.toSet());

        var hasUnmigratedVcs = allTacticalVcStrings.size() > migratedTacticalVcStrings.size();

        // check if we have unmigrated credentials alongside migrated ones
        if (hasUnmigratedVcs && !migratedTacticalVcStrings.isEmpty()) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                                    "Unmigrated tactical credentials found alongside migrated credentials")
                            .with(
                                    "migratedCris",
                                    getCriListString(
                                            tacticalVcs.stream()
                                                    .filter(vc -> vc.getMigrated() != null)
                                                    .toList()))
                            .with(
                                    "unmigratedCris",
                                    getCriListString(
                                            tacticalVcs.stream()
                                                    .filter(vc -> vc.getMigrated() == null)
                                                    .toList())));
        }

        // check all the tactical vcs are in the selected evcs vcs
        if (!hasUnmigratedVcs && !evcsVcStrings.containsAll(migratedTacticalVcStrings)) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                                    "Failed to find corresponding evcs credential for migrated tactical credential")
                            .with(
                                    "migratedCris",
                                    getCriListString(
                                            tacticalVcs.stream()
                                                    .filter(
                                                            vc ->
                                                                    evcsVcStrings.contains(
                                                                            vc.getVcString()))
                                                    .toList()))
                            .with(
                                    "unmigratedCris",
                                    getCriListString(
                                            tacticalVcs.stream()
                                                    .filter(
                                                            vc ->
                                                                    !evcsVcStrings.contains(
                                                                            vc.getVcString()))
                                                    .toList())));
        }

        // check all the evcs vcs are in the tactical store
        if (!hasUnmigratedVcs && !migratedTacticalVcStrings.containsAll(evcsVcStrings)) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                                    "Failed to find corresponding tactical credential for evcs credential")
                            .with("pendingEvcsCris", getCriListString(evcsVcs.get(PENDING_RETURN)))
                            .with("currentEvcsCris", getCriListString(evcsVcs.get(CURRENT)))
                            .with("tacticalCris", getCriListString(tacticalVcs)));
        }
    }

    private static String getCriListString(List<VerifiableCredential> vcs) {
        if (vcs == null) {
            return "<none>";
        }
        return vcs.stream().map(vc -> vc.getCri().getId()).collect(Collectors.joining(","));
    }

    private JourneyResponse buildF2FIncompleteResponse(CriResponseItem faceToFaceRequest) {
        switch (faceToFaceRequest.getStatus()) {
            case CriResponseService.STATUS_PENDING -> {
                LOGGER.info(LogHelper.buildLogMessage("F2F cri pending verification."));
                return JOURNEY_PENDING;
            }
            case CriResponseService.STATUS_ERROR -> {
                LOGGER.warn(LogHelper.buildLogMessage("F2F cri error."));
                return JOURNEY_F2F_FAIL;
            }
            default -> {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                "F2F unexpected status: " + faceToFaceRequest.getStatus()));
                return JOURNEY_F2F_FAIL;
            }
        }
    }

    private Optional<JourneyResponse> checkForProfileMatch(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation,
            VerifiableCredentialBundle vcBundle,
            boolean areGpg45VcsCorrelated,
            List<ContraIndicator> contraIndicators)
            throws ParseException, VerifiableCredentialException, EvcsServiceException {
        // Check for attained vot from requested vots
        var strongestAttainedVotFromVtr =
                getStrongestAttainedVotForVtr(
                        clientOAuthSessionItem
                                .getParsedVtr()
                                .getRequestedVotsByStrengthDescending(),
                        vcBundle.credentials,
                        auditEventUser,
                        deviceInformation,
                        areGpg45VcsCorrelated,
                        contraIndicators);

        // vot achieved for vtr
        if (strongestAttainedVotFromVtr.isPresent()) {
            return Optional.of(
                    buildReuseResponse(
                            strongestAttainedVotFromVtr.get(),
                            ipvSessionItem,
                            vcBundle,
                            auditEventUser,
                            deviceInformation));
        }

        return Optional.empty();
    }

    private JourneyResponse buildF2FNoMatchResponse(
            boolean areGpg45VcsCorrelated,
            AuditEventUser auditEventUser,
            String deviceInformation,
            List<ContraIndicator> contraIndicators)
            throws ConfigException, MitigationRouteException {
        LOGGER.info(LogHelper.buildLogMessage("F2F return - failed to match a profile."));
        sendAuditEvent(
                !areGpg45VcsCorrelated
                        ? AuditEventTypes.IPV_F2F_CORRELATION_FAIL
                        : AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                auditEventUser,
                deviceInformation);
        var mitigatedCI = cimitUtilityService.hasMitigatedContraIndicator(contraIndicators);
        if (mitigatedCI.isPresent()) {
            var mitigationJourney =
                    cimitUtilityService
                            .getMitigatedCiJourneyResponse(mitigatedCI.get())
                            .map(JourneyResponse::getJourney)
                            .orElseThrow(
                                    () ->
                                            new MitigationRouteException(
                                                    String.format(
                                                            "Empty mitigation route for mitigated CI: %s",
                                                            mitigatedCI.get())));
            if (!JOURNEY_ENHANCED_VERIFICATION_PATH.equals(mitigationJourney)) {
                throw new MitigationRouteException(
                        String.format("Unsupported mitigation route: %s", mitigationJourney));
            }
            return JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL;
        }
        return JOURNEY_F2F_FAIL;
    }

    private JourneyResponse buildNoMatchResponse(
            List<ContraIndicator> contraIndicators, Vot preferredNewIdentityLevel)
            throws ConfigException, MitigationRouteException {

        var mitigatedCI = cimitUtilityService.hasMitigatedContraIndicator(contraIndicators);
        if (mitigatedCI.isPresent()) {
            return cimitUtilityService
                    .getMitigatedCiJourneyResponse(mitigatedCI.get())
                    .orElseThrow(
                            () ->
                                    new MitigationRouteException(
                                            String.format(
                                                    "Empty mitigation route for mitigated CI: %s",
                                                    mitigatedCI.get())));
        }

        if (preferredNewIdentityLevel == Vot.P1) {
            LOGGER.info(LogHelper.buildLogMessage("New P1 IPV journey required"));
            return JOURNEY_IPV_GPG45_LOW;
        }

        LOGGER.info(LogHelper.buildLogMessage("New P2 IPV journey required"));
        return JOURNEY_IPV_GPG45_MEDIUM;
    }

    private JourneyResponse buildReuseResponse(
            Vot attainedVot,
            IpvSessionItem ipvSessionItem,
            VerifiableCredentialBundle vcBundle,
            AuditEventUser auditEventUser,
            String deviceInformation)
            throws VerifiableCredentialException, EvcsServiceException {
        // check the result of 6MFC and return the appropriate journey
        if (configService.enabled(REPEAT_FRAUD_CHECK)
                && attainedVot.getProfileType() == GPG45
                && allFraudVcsAreExpired(vcBundle.credentials)) {
            LOGGER.info(LogHelper.buildLogMessage("Expired fraud VC found"));
            sessionCredentialsService.persistCredentials(
                    allVcsExceptFraud(vcBundle.credentials), auditEventUser.getSessionId(), false);

            migrateCredentialsToEVCS(auditEventUser, deviceInformation, vcBundle);
            return JOURNEY_REPEAT_FRAUD_CHECK;
        }

        LOGGER.info(LogHelper.buildLogMessage("Returning reuse journey"));
        sendAuditEvent(
                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE, auditEventUser, deviceInformation);

        ipvSessionItem.setVot(attainedVot);
        ipvSessionService.updateIpvSession(ipvSessionItem);

        if (attainedVot.getProfileType() == OPERATIONAL_HMRC) {
            boolean isCurrentlyMigrating = ipvSessionItem.isInheritedIdentityReceivedThisSession();

            sessionCredentialsService.persistCredentials(
                    VcHelper.filterVCBasedOnProfileType(vcBundle.credentials, OPERATIONAL_HMRC),
                    auditEventUser.getSessionId(),
                    isCurrentlyMigrating);

            return isCurrentlyMigrating
                    ? JOURNEY_IN_MIGRATION_REUSE
                    : JOURNEY_OPERATIONAL_PROFILE_REUSE;
        }

        sessionCredentialsService.persistCredentials(
                VcHelper.filterVCBasedOnProfileType(
                        vcBundle.credentials, attainedVot.getProfileType()),
                auditEventUser.getSessionId(),
                false);

        migrateCredentialsToEVCS(auditEventUser, deviceInformation, vcBundle);

        return vcBundle.isPendingEvcsIdentity() ? JOURNEY_REUSE_WITH_STORE : JOURNEY_REUSE;
    }

    private void migrateCredentialsToEVCS(
            AuditEventUser auditEventUser,
            String deviceInformation,
            VerifiableCredentialBundle vcBundle)
            throws EvcsServiceException, VerifiableCredentialException {
        if (configService.enabled(EVCS_WRITE_ENABLED) && !vcBundle.hasEvcsIdentity()) {
            try {
                evcsMigrationService.migrateExistingIdentity(
                        auditEventUser.getUserId(), vcBundle.credentials());
                sendVCsMigratedAuditEvent(
                        auditEventUser, vcBundle.credentials(), deviceInformation);
            } catch (EvcsServiceException e) {
                if (configService.enabled(EVCS_READ_ENABLED)) {
                    throw e;
                } else {
                    LOGGER.error(
                            LogHelper.buildErrorMessage(
                                    "Failed to store EVCS migrated identity", e));
                }
            }
        }
    }

    private List<VerifiableCredential> allVcsExceptFraud(List<VerifiableCredential> vcs) {
        return vcs.stream().filter(vc -> !EXPERIAN_FRAUD.equals(vc.getCri())).toList();
    }

    private boolean allFraudVcsAreExpired(List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(vc -> vc.getCri() == EXPERIAN_FRAUD)
                .allMatch(VcHelper::isExpiredFraudVc);
    }

    private void sendAuditEvent(
            AuditEventTypes auditEventTypes,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        auditEventTypes,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }

    private void sendVCsMigratedAuditEvent(
            AuditEventUser auditEventUser,
            List<VerifiableCredential> credentials,
            String deviceInformation) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_VCS_MIGRATED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionsEvcsMigration(
                                extractSignaturesFromCredentials(credentials)),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }

    private List<String> extractSignaturesFromCredentials(List<VerifiableCredential> credentials) {
        return credentials.stream().map(vc -> vc.getVcString().split("\\.")[2]).toList();
    }

    private JourneyResponse buildErrorResponse(ErrorResponse errorResponse, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return new JourneyErrorResponse(
                JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse);
    }

    private Optional<Vot> getStrongestAttainedVotForVtr(
            List<Vot> requestedVotsByStrength,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser,
            String deviceInformation,
            boolean areGpg45VcsCorrelated,
            List<ContraIndicator> contraIndicators)
            throws ParseException {

        for (Vot requestedVot : requestedVotsByStrength) {
            boolean requestedVotAttained = false;
            if (requestedVot.getProfileType().equals(GPG45)) {
                if (areGpg45VcsCorrelated) {
                    requestedVotAttained =
                            achievedWithGpg45Profile(
                                    requestedVot,
                                    VcHelper.filterVCBasedOnProfileType(vcs, GPG45),
                                    auditEventUser,
                                    deviceInformation,
                                    contraIndicators);
                }
            } else {
                requestedVotAttained = hasOperationalProfileVc(requestedVot, vcs, contraIndicators);
            }

            if (requestedVotAttained) {
                return Optional.of(requestedVot);
            }
        }
        return Optional.empty();
    }

    private boolean achievedWithGpg45Profile(
            Vot requestedVot,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser,
            String deviceInformation,
            List<ContraIndicator> contraIndicators)
            throws ParseException {
        Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(vcs);
        Optional<Gpg45Profile> matchedGpg45Profile =
                !userIdentityService.checkRequiresAdditionalEvidence(vcs)
                        ? gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, requestedVot.getSupportedGpg45Profiles())
                        : Optional.empty();

        var isBreaching =
                cimitUtilityService.isBreachingCiThreshold(contraIndicators, requestedVot);

        // Successful match
        if (matchedGpg45Profile.isPresent() && !isBreaching) {
            var gpg45Credentials = new ArrayList<VerifiableCredential>();
            for (var vc : vcs) {
                if (!VcHelper.isOperationalProfileVc(vc)) {
                    gpg45Credentials.add(vc);
                }
            }
            LOGGER.info(
                    LogHelper.buildLogMessage("GPG45 profile has been met.")
                            .with(
                                    LOG_GPG45_PROFILE.getFieldName(),
                                    matchedGpg45Profile.get().getLabel()));
            sendProfileMatchedAuditEvent(
                    matchedGpg45Profile.get(),
                    gpg45Scores,
                    gpg45Credentials,
                    auditEventUser,
                    deviceInformation);

            return true;
        }
        return false;
    }

    private boolean hasOperationalProfileVc(
            Vot requestedVot,
            List<VerifiableCredential> vcs,
            List<ContraIndicator> contraIndicators)
            throws ParseException {
        for (var vc : vcs) {
            String credentialVot = vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME);
            Optional<String> matchedOperationalProfile =
                    requestedVot.getSupportedOperationalProfiles().stream()
                            .map(OperationalProfile::name)
                            .filter(profileName -> profileName.equals(credentialVot))
                            .findFirst();

            var isBreaching =
                    cimitUtilityService.isBreachingCiThreshold(contraIndicators, requestedVot);

            // Successful match
            if (matchedOperationalProfile.isPresent() && !isBreaching) {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Operational profile matched")
                                .with(LOG_VOT.getFieldName(), requestedVot));
                return true;
            }
        }
        return false;
    }

    private void sendProfileMatchedAuditEvent(
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        var auditEvent =
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionGpg45ProfileMatched(
                                gpg45Profile,
                                gpg45Scores,
                                VcHelper.extractTxnIdsFromCredentials(vcs)),
                        new AuditRestrictedDeviceInformation(deviceInformation));
        auditService.sendAuditEvent(auditEvent);
    }
}
