package uk.gov.di.ipv.core.processcandidateidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.ais.enums.AisInterventionType;
import uk.gov.di.ipv.core.library.ais.exception.AccountInterventionException;
import uk.gov.di.ipv.core.library.ais.exception.AisClientException;
import uk.gov.di.ipv.core.library.ais.service.AisService;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnknownProcessIdentityTypeException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.VotHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.ticf.TicfCriService;
import uk.gov.di.ipv.core.library.ticf.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.domain.SharedAuditEventParameters;
import uk.gov.di.ipv.core.processcandidateidentity.service.CheckCoiService;
import uk.gov.di.ipv.core.processcandidateidentity.service.StoreIdentityService;
import uk.gov.di.model.Intervention;
import uk.gov.di.model.RiskAssessment;
import uk.gov.di.model.RiskAssessmentCredential;

import java.io.UncheckedIOException;
import java.text.ParseException;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import static java.lang.Boolean.TRUE;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_ACCOUNT_BLOCKED;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_ACCOUNT_SUSPENDED;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_ACCOUNT_UNBLOCKED;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_ACCOUNT_UNSUSPENDED;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.ais.enums.AisInterventionType.AIS_NO_INTERVENTION;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.AIS_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.STORED_IDENTITY_SERVICE;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_CALLING_AIS_API;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_SECURITY_CHECK_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.enums.CandidateIdentityType.EXISTING;
import static uk.gov.di.ipv.core.library.enums.CandidateIdentityType.NEW;
import static uk.gov.di.ipv.core.library.enums.CandidateIdentityType.PENDING;
import static uk.gov.di.ipv.core.library.enums.CandidateIdentityType.REVERIFICATION;
import static uk.gov.di.ipv.core.library.enums.CandidateIdentityType.UPDATE;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ACCOUNT_INTERVENTION_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PROFILE_UNMET_PATH;

public class ProcessCandidateIdentityHandler
        implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private static final JourneyResponse JOURNEY_PROFILE_UNMET =
            new JourneyResponse(JOURNEY_PROFILE_UNMET_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final JourneyResponse JOURNEY_COI_CHECK_FAILED =
            new JourneyResponse(JOURNEY_COI_CHECK_FAILED_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private static final JourneyResponse JOURNEY_ACCOUNT_INTERVENTION =
            new JourneyResponse(JOURNEY_ACCOUNT_INTERVENTION_PATH);
    private static final Map<String, AisInterventionType> interventionCodeTypes =
            Map.of(
                    "00", AIS_NO_INTERVENTION,
                    "01", AIS_ACCOUNT_SUSPENDED,
                    "02", AIS_ACCOUNT_UNSUSPENDED,
                    "03", AIS_ACCOUNT_BLOCKED,
                    "04", AIS_FORCED_USER_PASSWORD_RESET,
                    "05", AIS_FORCED_USER_IDENTITY_VERIFY,
                    "06", AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY,
                    "07", AIS_ACCOUNT_UNBLOCKED);

    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final IpvSessionService ipvSessionService;
    private final SessionCredentialsService sessionCredentialsService;
    private final AuditService auditService;
    private final CimitService cimitService;
    private final CheckCoiService checkCoiService;
    private final CriStoringService criStoringService;
    private final UserIdentityService userIdentityService;
    private final StoreIdentityService storeIdentityService;
    private final VotMatcher votMatcher;
    private final TicfCriService ticfCriService;
    private final CimitUtilityService cimitUtilityService;
    private final EvcsService evcsService;
    private final AisService aisService;

    // Candidate identities that should be subject to a COI check
    private static final Set<CandidateIdentityType> COI_CHECK_TYPES =
            EnumSet.of(NEW, PENDING, REVERIFICATION, UPDATE);

    // Candidate identities that should store the given identity (if successful)
    private static final Set<CandidateIdentityType> STORE_IDENTITY_TYPES =
            EnumSet.of(NEW, PENDING, UPDATE);

    // Candidate identities that should match a profile
    private static final Set<CandidateIdentityType> PROFILE_MATCHING_TYPES =
            EnumSet.of(NEW, UPDATE, EXISTING);

    // Candidate identities that should not be checked against AIS
    private static final Set<CandidateIdentityType> SKIP_AIS_TYPES = EnumSet.of(REVERIFICATION);

    @ExcludeFromGeneratedCoverageReport
    public ProcessCandidateIdentityHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessCandidateIdentityHandler(ConfigService configService) {
        this.auditService = AuditService.create(configService);
        this.cimitService = new CimitService(configService);
        this.configService = configService;
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.checkCoiService = new CheckCoiService(configService, auditService);
        this.userIdentityService = new UserIdentityService(configService);
        this.storeIdentityService = new StoreIdentityService(configService, auditService);
        this.ticfCriService = new TicfCriService(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.votMatcher =
                new VotMatcher(
                        userIdentityService, new Gpg45ProfileEvaluator(), cimitUtilityService);
        this.criStoringService =
                new CriStoringService(
                        configService, auditService, null, sessionCredentialsService, cimitService);
        this.evcsService = new EvcsService(configService);
        this.aisService = new AisService(configService);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    @ExcludeFromGeneratedCoverageReport
    public ProcessCandidateIdentityHandler(
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            IpvSessionService ipvSessionService,
            CheckCoiService checkCoiService,
            SessionCredentialsService sessionCredentialsService,
            CriStoringService criStoringService,
            AuditService auditService,
            CimitService cimitService,
            UserIdentityService userIdentityService,
            StoreIdentityService storeIdentityService,
            VotMatcher votMatcher,
            CimitUtilityService cimitUtilityService,
            TicfCriService ticfCriService,
            EvcsService evcsService,
            AisService aisService) {
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.ipvSessionService = ipvSessionService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.checkCoiService = checkCoiService;
        this.cimitService = cimitService;
        this.userIdentityService = userIdentityService;
        this.auditService = auditService;
        this.criStoringService = criStoringService;
        this.votMatcher = votMatcher;
        this.storeIdentityService = storeIdentityService;
        this.ticfCriService = ticfCriService;
        this.cimitUtilityService = cimitUtilityService;
        this.evcsService = evcsService;
        this.aisService = aisService;
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    @SuppressWarnings("java:S3776")
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));

        IpvSessionItem ipvSessionItem = null;

        try {
            var ipvSessionId = RequestHelper.getIpvSessionId(request);
            var ipAddress = request.getIpAddress();
            var deviceInformation = request.getDeviceInformation();
            var processIdentityType = RequestHelper.getProcessIdentityType(request);

            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            String userId = clientOAuthSessionItem.getUserId();

            // We skip AIS checks for reverification journeys
            if (configService.enabled(AIS_ENABLED)
                    && !SKIP_AIS_TYPES.contains(processIdentityType)) {
                var interventionState = aisService.fetchAccountState(userId);
                if (midJourneyInterventionDetected(
                        ipvSessionItem.getInitialAccountInterventionState(), interventionState)) {
                    throw new AccountInterventionException();
                }
                ipvSessionItem.setInitialAccountInterventionState(interventionState);
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }

            var sessionVcs =
                    sessionCredentialsService.getCredentials(
                            ipvSessionItem.getIpvSessionId(), userId);

            var auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            return processCandidateThroughJourney(
                    processIdentityType,
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    deviceInformation,
                    ipAddress,
                    sessionVcs,
                    auditEventUser);
        } catch (AccountInterventionException e) {
            updateIpvSessionWithIntervention(ipvSessionItem);
            return JOURNEY_ACCOUNT_INTERVENTION.toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            var errorMessage = LogHelper.buildErrorMessage("Failed to process identity", e);
            if (ErrorResponse.FAILED_NAME_CORRELATION.equals(e.getErrorResponse())) {
                LOGGER.info(errorMessage);
            } else {
                LOGGER.error(errorMessage);
            }
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (UnknownProcessIdentityTypeException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unknown process identity type", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.BAD_REQUEST,
                            UNEXPECTED_PROCESS_IDENTITY_TYPE)
                    .toObjectMap();
        } catch (AisClientException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to call AIS API", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            ERROR_CALLING_AIS_API)
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to find ipv session", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (VerifiableCredentialException | EvcsServiceException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to store identity", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (ParseException | CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse credentials", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (CiExtractionException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(FAILED_TO_EXTRACT_CIS_FROM_VC.getMessage(), e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            FAILED_TO_EXTRACT_CIS_FROM_VC)
                    .toObjectMap();
        } catch (UncheckedIOException e) {
            // Temporary mitigation to force lambda instance to crash and restart by explicitly
            // exiting the program on fatal IOException - see PYIC-8220 and incident INC0014398.
            LOGGER.error("Crashing on UncheckedIOException", e);
            System.exit(1);
            return null;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private void updateIpvSessionWithIntervention(IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setErrorCode("session_invalidated");
        ipvSessionItem.setErrorDescription("Account intervention detected");
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }

    private boolean midJourneyInterventionDetected(
            AccountInterventionState initialAccountInterventionState,
            AccountInterventionState currentAccountInterventionState) {
        // If no intervention flags are set then there can't have been an intervention
        if (!initialAccountInterventionState.isBlocked()
                && !initialAccountInterventionState.isSuspended()
                && !initialAccountInterventionState.isResetPassword()
                && !initialAccountInterventionState.isReproveIdentity()
                && !currentAccountInterventionState.isBlocked()
                && !currentAccountInterventionState.isSuspended()
                && !currentAccountInterventionState.isResetPassword()
                && !currentAccountInterventionState.isReproveIdentity()) {
            return false;
        }

        // If the user is currently reproving their identity then the suspended and reprove identity
        // flags may not have been reset yet.
        if (notBlockedAndNotPasswordReset(
                        initialAccountInterventionState, currentAccountInterventionState)
                && initialAccountInterventionState.isSuspended()
                && currentAccountInterventionState.isSuspended()
                && initialAccountInterventionState.isReproveIdentity()
                && currentAccountInterventionState.isReproveIdentity()) {
            return false;
        }

        // If the user is currently reproving their identity and it has been detected
        if (notBlockedAndNotPasswordReset(
                        initialAccountInterventionState, currentAccountInterventionState)
                && initialAccountInterventionState.isSuspended()
                && !currentAccountInterventionState.isSuspended()
                && initialAccountInterventionState.isReproveIdentity()
                && !currentAccountInterventionState.isReproveIdentity()) {
            return false;
        }

        // Otherwise an intervention flag has been set for some other reason
        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Mid journey intervention detected. Initial state: %s Final state: %s"
                                    .formatted(
                                            OBJECT_MAPPER.writeValueAsString(
                                                    initialAccountInterventionState),
                                            OBJECT_MAPPER.writeValueAsString(
                                                    currentAccountInterventionState))));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Error converting account intervention state to string", e));
            LOGGER.info(LogHelper.buildLogMessage("Mid journey intervention detected."));
        }
        return true;
    }

    private boolean notBlockedAndNotPasswordReset(
            AccountInterventionState initialAccountInterventionState,
            AccountInterventionState currentAccountInterventionState) {
        return !initialAccountInterventionState.isBlocked()
                && !initialAccountInterventionState.isResetPassword()
                && !currentAccountInterventionState.isBlocked()
                && !currentAccountInterventionState.isResetPassword();
    }

    private CoiCheckType getCoiCheckType(
            CandidateIdentityType identityType, ClientOAuthSessionItem clientOAuthSessionItem) {
        if (REVERIFICATION.equals(identityType)) {
            return CoiCheckType.REVERIFICATION;
        }

        if (TRUE.equals(clientOAuthSessionItem.getReproveIdentity())) {
            return CoiCheckType.ACCOUNT_INTERVENTION;
        }

        return CoiCheckType.STANDARD;
    }

    private Map<String, Object> processCandidateThroughJourney(
            CandidateIdentityType processIdentityType,
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress,
            List<VerifiableCredential> sessionVcs,
            AuditEventUser auditEventUser)
            throws EvcsServiceException,
                    HttpResponseExceptionWithErrorBody,
                    CredentialParseException,
                    ParseException,
                    CiExtractionException,
                    AccountInterventionException {
        List<EvcsGetUserVCDto> evcsUserVcs = null;
        var userId = clientOAuthSessionItem.getUserId();
        var auditEventParameters =
                new SharedAuditEventParameters(auditEventUser, deviceInformation);

        // These identity types require the VCs from EVCS. To save multiple calls,
        // we call for them once here.
        if (requiresExistingVcsFromEvcs(processIdentityType)) {
            evcsUserVcs =
                    evcsService.getUserVCs(
                            userId,
                            clientOAuthSessionItem.getEvcsAccessToken(),
                            CURRENT,
                            PENDING_RETURN);
        }

        if (COI_CHECK_TYPES.contains(processIdentityType)) {
            var coiCheckType = getCoiCheckType(processIdentityType, clientOAuthSessionItem);
            LOGGER.info(
                    LogHelper.buildLogMessage("Performing COI check")
                            .with(LOG_CHECK_TYPE.getFieldName(), coiCheckType.name()));

            var isCoiCheckSuccessful =
                    checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            coiCheckType,
                            sessionVcs,
                            evcsUserVcs,
                            auditEventParameters);

            if (!isCoiCheckSuccessful) {
                return JOURNEY_COI_CHECK_FAILED.toObjectMap();
            }
        }

        boolean areVcsCorrelated = false;
        VotMatchingResult votMatchingResult = null;
        if (requiresVotMatchingResult(processIdentityType)) {
            areVcsCorrelated = userIdentityService.areVcsCorrelated(sessionVcs);
            votMatchingResult =
                    getVotMatchingResult(
                            ipvSessionItem, clientOAuthSessionItem, sessionVcs, areVcsCorrelated);
        }

        if (PROFILE_MATCHING_TYPES.contains(processIdentityType)) {
            LOGGER.info(LogHelper.buildLogMessage("Performing profile evaluation"));
            var journey =
                    getJourneyResponseForProfileMatching(
                            ipvSessionItem,
                            sessionVcs,
                            areVcsCorrelated,
                            votMatchingResult,
                            auditEventParameters);

            if (journey != null) {
                return journey.toObjectMap();
            }
        }

        if (configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId())) {
            LOGGER.info(LogHelper.buildLogMessage("Performing TICF CRI call"));
            var journey =
                    getJourneyResponseFromTicfCall(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            ipAddress,
                            auditEventParameters);

            if (journey != null) {
                // We still store a pending identity - it might be mitigating an existing CI
                if (PENDING.equals(processIdentityType)) {
                    LOGGER.info(LogHelper.buildLogMessage("Storing identity"));
                    storeCandidateIdentity(
                            userId,
                            ipvSessionItem,
                            null,
                            sessionVcs,
                            evcsUserVcs,
                            processIdentityType,
                            auditEventParameters);
                }
                return journey.toObjectMap();
            }
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }

        if (shouldStoreIdentity(processIdentityType)) {
            LOGGER.info(LogHelper.buildLogMessage("Storing identity"));
            storeCandidateIdentity(
                    userId,
                    ipvSessionItem,
                    votMatchingResult,
                    sessionVcs,
                    evcsUserVcs,
                    processIdentityType,
                    auditEventParameters);
        }

        return JOURNEY_NEXT.toObjectMap();
    }

    private void storeCandidateIdentity(
            String userId,
            IpvSessionItem ipvSessionItem,
            VotMatchingResult votMatchingResult,
            List<VerifiableCredential> sessionVcs,
            List<EvcsGetUserVCDto> evcsUserVcs,
            CandidateIdentityType processIdentityType,
            SharedAuditEventParameters auditEventParameters)
            throws EvcsServiceException {
        var achievedVot = ipvSessionItem.getVot();
        VotMatchingResult.VotAndProfile strongestMatchedVot =
                Objects.isNull(votMatchingResult)
                        ? null
                        : votMatchingResult.strongestMatch().orElse(null);

        var securityCheckCredential = ipvSessionItem.getSecurityCheckCredential();

        if (StringUtils.isNotBlank(securityCheckCredential)
                && configService.enabled(STORED_IDENTITY_SERVICE)) {
            try {
                var parsedSecurityCheckVc =
                        cimitUtilityService.getParsedSecurityCheckCredential(
                                securityCheckCredential, userId);
                sessionVcs.add(parsedSecurityCheckVc);
            } catch (CredentialParseException e) {
                LOGGER.warn(
                        "Failed to parse security check credential, skipping storage of CIMIT VC");
            }
        }

        storeIdentityService.storeIdentity(
                userId,
                sessionVcs,
                evcsUserVcs,
                achievedVot,
                strongestMatchedVot,
                processIdentityType,
                auditEventParameters);
    }

    private boolean requiresVotMatchingResult(CandidateIdentityType processIdentityType) {
        if (shouldStoreExistingIdentity(processIdentityType)) {
            return true;
        }

        var typesRequiringVotMatchingResult =
                Stream.concat(PROFILE_MATCHING_TYPES.stream(), STORE_IDENTITY_TYPES.stream())
                        .filter(identityType -> !identityType.equals(PENDING))
                        .distinct()
                        .toList();

        return typesRequiringVotMatchingResult.contains(processIdentityType);
    }

    private boolean requiresExistingVcsFromEvcs(CandidateIdentityType processIdentityType) {
        return COI_CHECK_TYPES.contains(processIdentityType)
                || shouldStoreIdentity(processIdentityType);
    }

    private boolean shouldStoreIdentity(CandidateIdentityType identityType) {
        return STORE_IDENTITY_TYPES.contains(identityType)
                || shouldStoreExistingIdentity(identityType);
    }

    private boolean shouldStoreExistingIdentity(CandidateIdentityType identityType) {
        return configService.enabled(STORED_IDENTITY_SERVICE) && EXISTING.equals(identityType);
    }

    private JourneyResponse getJourneyResponseForProfileMatching(
            IpvSessionItem ipvSessionItem,
            List<VerifiableCredential> sessionVcs,
            boolean areVcsCorrelated,
            VotMatchingResult votMatchingResult,
            SharedAuditEventParameters sharedAuditEventParameters) {

        if (!areVcsCorrelated) {
            return JOURNEY_VCS_NOT_CORRELATED;
        }

        var strongestRequestedMatch = votMatchingResult.strongestRequestedMatch();

        if (strongestRequestedMatch.isEmpty()) {
            return JOURNEY_PROFILE_UNMET;
        }

        var matchedVot = strongestRequestedMatch.get();
        ipvSessionItem.setVot(matchedVot.vot());
        ipvSessionService.updateIpvSession(ipvSessionItem);

        if (matchedVot.vot().getProfileType() == ProfileType.GPG45) {
            var profile = matchedVot.profile();
            if (profile.isEmpty()) {
                throw new IllegalArgumentException(
                        "Matched GPG45 vot result does not have a profile");
            }
            sendProfileMatchedAuditEvent(
                    profile.get(),
                    votMatchingResult.gpg45Scores(),
                    VcHelper.filterVCBasedOnProfileType(sessionVcs, ProfileType.GPG45),
                    sharedAuditEventParameters);
        }

        return null;
    }

    public JourneyResponse getJourneyResponseFromTicfCall(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String ipAddress,
            SharedAuditEventParameters sharedAuditEventParameters)
            throws AccountInterventionException {
        try {
            // If we have an invalid ClientOauthSessionItem (e.g. as a result of failed JAR request
            // validation), we cannot make a request to TICF as we will have missing required
            // properties.
            if (clientOAuthSessionItem.isErrorClientSession()) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                "Invalid ClientOauthSessionItem. Skipping TICF call."));
                return null;
            }

            // We must check if the security check credential on the session is empty.
            // This can happen when an error occurs prior to the first call to get the
            // security check credential e.g. in the check-existing-identity lambda.
            // If it is, we need to make a call to CIMIT prior to getting the TICF VC
            // in order to get the mitigation information unaffected by this new VC.
            String previousSecurityCheckCredential = ipvSessionItem.getSecurityCheckCredential();
            if (!clientOAuthSessionItem.isReverification()
                    && StringUtils.isBlank(previousSecurityCheckCredential)) {
                previousSecurityCheckCredential =
                        cimitService
                                .fetchContraIndicatorsVc(
                                        clientOAuthSessionItem.getUserId(),
                                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                                        ipAddress,
                                        ipvSessionItem)
                                .getVcString();
            }

            var ticfVcs = ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem);

            if (ticfVcs.isEmpty()) {
                LOGGER.warn(LogHelper.buildLogMessage("No TICF VC to process - returning next"));
                return null;
            }

            criStoringService.storeVcs(
                    TICF,
                    ipAddress,
                    sharedAuditEventParameters.deviceInformation(),
                    ticfVcs,
                    clientOAuthSessionItem,
                    ipvSessionItem,
                    List.of(),
                    sharedAuditEventParameters.auditEventUser());

            if (configService.enabled(AIS_ENABLED)
                    && checkHasRelevantIntervention(ipvSessionItem, ticfVcs)) {
                throw new AccountInterventionException();
            }

            if (!clientOAuthSessionItem.isReverification()) {
                // Get mitigations from old CIMIT VC to compare against the mitigations on the new
                // CIs
                var targetVot = VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem);
                var oldMitigations =
                        cimitUtilityService.getMitigationEventIfBreachingOrActive(
                                previousSecurityCheckCredential,
                                clientOAuthSessionItem.getUserId(),
                                targetVot);

                var contraIndicatorsVc =
                        cimitService.fetchContraIndicatorsVc(
                                clientOAuthSessionItem.getUserId(),
                                clientOAuthSessionItem.getGovukSigninJourneyId(),
                                ipAddress,
                                ipvSessionItem);
                var newCis = cimitUtilityService.getContraIndicatorsFromVc(contraIndicatorsVc);
                var newMitigations =
                        cimitUtilityService.getMitigationEventIfBreachingOrActive(
                                newCis, targetVot);

                // If breaching and no available mitigations or a new mitigation is required, we
                // return fail-with-ci
                if (cimitUtilityService.isBreachingCiThreshold(newCis, targetVot)
                        && (newMitigations.isEmpty() || !newMitigations.equals(oldMitigations))) {
                    LOGGER.info(
                            LogHelper.buildLogMessage(
                                    "CI score is breaching threshold - setting VOT to P0"));
                    ipvSessionItem.setVot(Vot.P0);
                    ipvSessionService.updateIpvSession(ipvSessionItem);
                    return JOURNEY_FAIL_WITH_CI;
                }

                LOGGER.info(LogHelper.buildLogMessage("CI score not breaching threshold"));
            }

            return null;
        } catch (TicfCriServiceException
                | VerifiableCredentialException
                | CiPostMitigationsException
                | CiPutException
                | CiRetrievalException
                | CiExtractionException
                | ConfigException
                | CredentialParseException
                | UnrecognisedVotException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error processing response from TICF CRI", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ERROR_PROCESSING_TICF_CRI_RESPONSE);
        }
    }

    private boolean checkHasRelevantIntervention(
            IpvSessionItem ipvSessionItem, List<VerifiableCredential> ticfVcs) {

        return ticfVcs.stream()
                .filter(vc -> vc.getCredential() instanceof RiskAssessmentCredential)
                .flatMap(
                        vc ->
                                ((RiskAssessmentCredential) vc.getCredential())
                                        .getEvidence().stream())
                .map(RiskAssessment::getIntervention)
                .filter(Objects::nonNull)
                .map(Intervention::getInterventionCode)
                .filter(Objects::nonNull)
                .map(
                        interventionCode ->
                                aisService.getStateByIntervention(
                                        interventionCodeTypes.get(interventionCode)))
                .anyMatch(
                        interventionState ->
                                midJourneyInterventionDetected(
                                        ipvSessionItem.getInitialAccountInterventionState(),
                                        interventionState));
    }

    private void sendProfileMatchedAuditEvent(
            Gpg45Profile matchedProfile,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> vcs,
            SharedAuditEventParameters sharedAuditEventParameters) {
        var auditEvent =
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        sharedAuditEventParameters.auditEventUser(),
                        new AuditExtensionGpg45ProfileMatched(
                                matchedProfile,
                                gpg45Scores,
                                VcHelper.extractTxnIdsFromCredentials(vcs)),
                        new AuditRestrictedDeviceInformation(
                                sharedAuditEventParameters.deviceInformation()));
        auditService.sendAuditEvent(auditEvent);
    }

    private VotMatchingResult getVotMatchingResult(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            List<VerifiableCredential> sessionVcs,
            boolean areVcsCorrelated)
            throws CiExtractionException,
                    CredentialParseException,
                    ParseException,
                    HttpResponseExceptionWithErrorBody {
        if (StringUtils.isBlank(ipvSessionItem.getSecurityCheckCredential())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, MISSING_SECURITY_CHECK_CREDENTIAL);
        }

        var contraIndicators =
                cimitUtilityService.getContraIndicatorsFromVc(
                        ipvSessionItem.getSecurityCheckCredential(),
                        clientOAuthSessionItem.getUserId());

        return votMatcher.findStrongestMatches(
                clientOAuthSessionItem.getVtrAsVots(),
                sessionVcs,
                contraIndicators,
                areVcsCorrelated);
    }
}
