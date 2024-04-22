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
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.OperationalProfile;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem.EvidenceType;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.INHERITED_IDENTITY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REPEAT_FRAUD_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_RESET_GPG45_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_RESET_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_PATH;

/** Check Existing Identity response Lambda */
public class CheckExistingIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_OPERATIONAL_PROFILE_REUSE =
            new JourneyResponse(JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH);
    private static final JourneyResponse JOURNEY_IN_MIGRATION_REUSE =
            new JourneyResponse(JOURNEY_IN_MIGRATION_REUSE_PATH);
    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_IPV_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL =
            new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_RESET_IDENTITY =
            new JourneyResponse(JOURNEY_RESET_IDENTITY_PATH);
    private static final JourneyResponse JOURNEY_RESET_GPG45_IDENTITY =
            new JourneyResponse(JOURNEY_RESET_GPG45_IDENTITY_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET_PATH);
    private static final JourneyResponse JOURNEY_REPEAT_FRAUD_CHECK =
            new JourneyResponse(JOURNEY_REPEAT_FRAUD_CHECK_PATH);
    public static final List<Vot> SUPPORTED_VOTS_BY_STRENGTH =
            List.of(Vot.P2, Vot.PCL250, Vot.PCL200);

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CiMitService ciMitService;
    private final CiMitUtilityService ciMitUtilityService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final SessionCredentialsService sessionCredentialsService;

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
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.sessionCredentialsService = sessionCredentialsService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.auditService = new AuditService(AuditService.getSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.ciMitService = new CiMitService(configService);
        this.ciMitUtilityService = new CiMitUtilityService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            String ipvSessionId = getIpvSessionId(event);
            String ipAddress = getIpAddress(event);
            configService.setFeatureSet(RequestHelper.getFeatureSet(event));

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            return getJourneyResponse(ipvSessionItem, clientOAuthSessionItem, ipAddress)
                    .toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        }
    }

    @SuppressWarnings("java:S3776") // Cognitive Complexity of methods should not be too high
    @Tracing
    private JourneyResponse getJourneyResponse(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String ipAddress) {
        try {
            var ipvSessionId = ipvSessionItem.getIpvSessionId();
            var userId = clientOAuthSessionItem.getUserId();
            var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            var vcs = verifiableCredentialService.getVcs(userId);
            var hasF2fVc = vcs.stream().anyMatch(vc -> vc.getCriId().equals(F2F_CRI));
            CriResponseItem f2fRequest = criResponseService.getFaceToFaceRequest(userId);
            final boolean isF2FIncomplete = !Objects.isNull(f2fRequest) && !hasF2fVc;
            final boolean isF2FComplete = !Objects.isNull(f2fRequest) && hasF2fVc;

            var contraIndicators =
                    ciMitService.getContraIndicators(
                            clientOAuthSessionItem.getUserId(), govukSigninJourneyId, ipAddress);

            var ciScoringCheckResponse = checkForCIScoringFailure(contraIndicators);

            Optional<Boolean> reproveIdentity =
                    Optional.ofNullable(clientOAuthSessionItem.getReproveIdentity());

            if (reproveIdentity.orElse(false)) {
                return buildForceResetResponse(ciScoringCheckResponse.orElse(null));
            } else if (configService.enabled(RESET_IDENTITY)) {
                return buildForceGpg45ResetResponse(ciScoringCheckResponse.orElse(null));
            }

            if (ciScoringCheckResponse.isPresent()) {
                return isF2FIncomplete
                        ? buildF2FIncompleteResponse(
                                f2fRequest) // F2F mitigation journey in progress
                        : ciScoringCheckResponse.get(); // CI fail or mitigation journey
            }

            // Check for credentials correlation failure
            var areGpg45VcsCorrelated = userIdentityService.areVcsCorrelated(vcs);

            var profileMatchResponse =
                    checkForProfileMatch(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            auditEventUser,
                            vcs,
                            areGpg45VcsCorrelated);
            if (profileMatchResponse.isPresent()) {
                return profileMatchResponse.get();
            }

            // No profile matched but has a pending F2F request
            if (isF2FIncomplete) {
                return buildF2FIncompleteResponse(f2fRequest);
            }

            // No profile match
            return isF2FComplete
                    ? buildF2FNoMatchResponse(
                            areGpg45VcsCorrelated, auditEventUser, contraIndicators)
                    : buildNoMatchResponse(vcs, auditEventUser, contraIndicators);

        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return buildErrorResponse(e.getErrorResponse(), e);
        } catch (CiRetrievalException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_GET_STORED_CIS, e);
        } catch (ParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS, e);
        } catch (UnknownEvidenceTypeException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE, e);
        } catch (SqsException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT, e);
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

    @Tracing
    private JourneyResponse buildForceResetResponse(JourneyResponse ciScoringCheckResponse) {
        LOGGER.info(
                LogHelper.buildLogMessage("resetIdentity flag is enabled, reset users identity."));
        if (ciScoringCheckResponse != null) {
            if (JOURNEY_FAIL_WITH_CI.equals(ciScoringCheckResponse)) {
                // forces a reset of the user's identity if the CI breached and no
                // possible mitigation
                return JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET;
            }
            // sends the user on mitigation journey if the CI breached and mitigation is possible
            return ciScoringCheckResponse;
        }
        return JOURNEY_RESET_IDENTITY;
    }

    @Tracing
    private JourneyResponse buildForceGpg45ResetResponse(JourneyResponse ciScoringCheckResponse) {
        LOGGER.info(
                LogHelper.buildLogMessage("resetIdentity flag is enabled, reset users identity."));
        if (ciScoringCheckResponse != null) {
            if (JOURNEY_FAIL_WITH_CI.equals(ciScoringCheckResponse)) {
                // forces a reset of the user's identity if the CI breached and no
                // possible mitigation
                return JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET;
            }
            // sends the user on mitigation journey if the CI breached and mitigation is possible
            return ciScoringCheckResponse;
        }
        return JOURNEY_RESET_GPG45_IDENTITY;
    }

    @Tracing
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

    @Tracing
    private Optional<JourneyResponse> checkForCIScoringFailure(ContraIndicators contraIndicators)
            throws ConfigException {

        // CI scoring failure
        if (ciMitUtilityService.isBreachingCiThreshold(contraIndicators)) {
            return Optional.of(
                    ciMitUtilityService
                            .getCiMitigationJourneyResponse(contraIndicators)
                            .orElse(JOURNEY_FAIL_WITH_CI));
        }
        return Optional.empty();
    }

    @Tracing
    private Optional<JourneyResponse> checkForProfileMatch(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            AuditEventUser auditEventUser,
            List<VerifiableCredential> vcs,
            boolean areGpg45VcsCorrelated)
            throws ParseException, UnknownEvidenceTypeException, SqsException,
                    CredentialParseException, VerifiableCredentialException {
        // Check for attained vot from vtr
        var strongestAttainedVotFromVtr =
                getStrongestAttainedVotForVtr(
                        clientOAuthSessionItem.getVtr(),
                        vcs,
                        auditEventUser,
                        areGpg45VcsCorrelated);

        // vot achieved for vtr
        if (strongestAttainedVotFromVtr.isPresent()) {
            return Optional.of(
                    buildReuseResponse(
                            strongestAttainedVotFromVtr.get(),
                            ipvSessionItem,
                            vcs,
                            auditEventUser));
        }

        return Optional.empty();
    }

    private JourneyResponse buildF2FNoMatchResponse(
            boolean areGpg45VcsCorrelated,
            AuditEventUser auditEventUser,
            ContraIndicators contraIndicators)
            throws SqsException, ConfigException, MitigationRouteException {
        LOGGER.info(LogHelper.buildLogMessage("F2F return - failed to match a profile."));
        sendAuditEvent(
                !areGpg45VcsCorrelated
                        ? AuditEventTypes.IPV_F2F_CORRELATION_FAIL
                        : AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                auditEventUser);
        var mitigatedCI = ciMitUtilityService.hasMitigatedContraIndicator(contraIndicators);
        if (mitigatedCI.isPresent()) {
            var mitigationJourney =
                    ciMitUtilityService
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
            List<VerifiableCredential> verifiableCredentials,
            AuditEventUser auditEventUser,
            ContraIndicators contraIndicators)
            throws SqsException, ConfigException, MitigationRouteException {

        var mitigatedCI = ciMitUtilityService.hasMitigatedContraIndicator(contraIndicators);
        if (mitigatedCI.isPresent()) {
            return ciMitUtilityService
                    .getMitigatedCiJourneyResponse(mitigatedCI.get())
                    .orElseThrow(
                            () ->
                                    new MitigationRouteException(
                                            String.format(
                                                    "Empty mitigation route for mitigated CI: %s",
                                                    mitigatedCI.get())));
        }
        if (!VcHelper.filterVCBasedOnProfileType(verifiableCredentials, GPG45).isEmpty()) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Failed to match profile so resetting identity."));
            sendAuditEvent(AuditEventTypes.IPV_IDENTITY_REUSE_RESET, auditEventUser);

            return JOURNEY_RESET_GPG45_IDENTITY;
        }
        LOGGER.info(LogHelper.buildLogMessage("New IPV journey required"));
        return JOURNEY_IPV_GPG45_MEDIUM;
    }

    private JourneyResponse buildReuseResponse(
            Vot attainedVot,
            IpvSessionItem ipvSessionItem,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser)
            throws SqsException, VerifiableCredentialException {
        // check the result of 6MFC and return the appropriate journey
        if (configService.enabled(REPEAT_FRAUD_CHECK)
                && attainedVot.getProfileType() == GPG45
                && !hasCurrentFraudVc(vcs)) {
            LOGGER.info(LogHelper.buildLogMessage("Expired fraud VC found"));
            sessionCredentialsService.persistCredentials(
                    allVcsExceptFraud(vcs), auditEventUser.getSessionId(), false);
            return JOURNEY_REPEAT_FRAUD_CHECK;
        }

        LOGGER.info(LogHelper.buildLogMessage("Returning reuse journey"));
        sendAuditEvent(AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE, auditEventUser);

        ipvSessionItem.setVot(attainedVot);
        ipvSessionService.updateIpvSession(ipvSessionItem);

        if (attainedVot.getProfileType() == OPERATIONAL_HMRC) {
            // the only VC we should possibly have collected this session at this point is a
            // migration VC
            var vcReceivedThisSession = ipvSessionItem.getVcReceivedThisSession();
            boolean isOpProfileReuse =
                    vcReceivedThisSession == null || vcReceivedThisSession.isEmpty();

            sessionCredentialsService.persistCredentials(
                    VcHelper.filterVCBasedOnProfileType(vcs, OPERATIONAL_HMRC),
                    auditEventUser.getSessionId(),
                    !isOpProfileReuse);

            return isOpProfileReuse
                    ? JOURNEY_OPERATIONAL_PROFILE_REUSE
                    : JOURNEY_IN_MIGRATION_REUSE;
        }

        sessionCredentialsService.persistCredentials(
                VcHelper.filterVCBasedOnProfileType(vcs, attainedVot.getProfileType()),
                auditEventUser.getSessionId(),
                false);

        return JOURNEY_REUSE;
    }

    private List<VerifiableCredential> allVcsExceptFraud(List<VerifiableCredential> vcs) {
        return vcs.stream().filter(vc -> !EXPERIAN_FRAUD_CRI.equals(vc.getCriId())).toList();
    }

    private boolean hasCurrentFraudVc(List<VerifiableCredential> vcs) {
        var fraudVCs =
                VcHelper.filterVCBasedOnEvidenceType(
                        vcs, EvidenceType.IDENTITY_FRAUD, EvidenceType.FRAUD_WITH_ACTIVITY);
        for (var vc : fraudVCs) {
            if (!VcHelper.isExpiredFraudVc(vc)) {
                return true;
            }
        }
        return false;
    }

    private void sendAuditEvent(AuditEventTypes auditEventTypes, AuditEventUser auditEventUser)
            throws SqsException {
        auditService.sendAuditEvent(
                new AuditEvent(
                        auditEventTypes,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));
    }

    private JourneyResponse buildErrorResponse(ErrorResponse errorResponse, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return new JourneyErrorResponse(
                JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse);
    }

    @Tracing
    private Optional<Vot> getStrongestAttainedVotForVtr(
            List<String> vtr,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser,
            boolean areGpg45VcsCorrelated)
            throws UnknownEvidenceTypeException, ParseException, SqsException,
                    CredentialParseException {

        var requestedVotsByStrength =
                SUPPORTED_VOTS_BY_STRENGTH.stream()
                        .filter(vot -> vtr.contains(vot.name()))
                        .toList();

        for (var requestedVot : requestedVotsByStrength) {
            boolean requestedVotAttained = false;
            if (requestedVot.getProfileType().equals(GPG45)) {
                if (areGpg45VcsCorrelated) {
                    requestedVotAttained =
                            achievedWithGpg45Profile(
                                    requestedVot,
                                    VcHelper.filterVCBasedOnProfileType(vcs, GPG45),
                                    auditEventUser);
                }
            } else {
                requestedVotAttained = hasOperationalProfileVc(requestedVot, vcs);
            }

            if (requestedVotAttained) {
                return Optional.of(requestedVot);
            }
        }
        return Optional.empty();
    }

    private boolean achievedWithGpg45Profile(
            Vot requestedVot, List<VerifiableCredential> vcs, AuditEventUser auditEventUser)
            throws UnknownEvidenceTypeException, ParseException, SqsException,
                    CredentialParseException {

        Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(vcs);
        Optional<Gpg45Profile> matchedGpg45Profile =
                !userIdentityService.checkRequiresAdditionalEvidence(vcs)
                        ? gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, requestedVot.getSupportedGpg45Profiles())
                        : Optional.empty();

        // Successful match
        if (matchedGpg45Profile.isPresent()) {
            // remove weaker operational profile
            if (configService.enabled(INHERITED_IDENTITY) && requestedVot.equals(Vot.P2)) {
                verifiableCredentialService.deleteHmrcInheritedIdentityIfPresent(vcs);
            }

            var gpg45Credentials = new ArrayList<VerifiableCredential>();
            for (var vc : vcs) {
                if (!VcHelper.isOperationalProfileVc(vc)) {
                    gpg45Credentials.add(vc);
                }
            }
            sendProfileMatchedAuditEvent(
                    matchedGpg45Profile.get(), gpg45Scores, gpg45Credentials, auditEventUser);

            return true;
        }
        return false;
    }

    private boolean hasOperationalProfileVc(Vot requestedVot, List<VerifiableCredential> vcs)
            throws ParseException {
        for (var vc : vcs) {
            String credentialVot = vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME);
            Optional<String> matchedOperationalProfile =
                    requestedVot.getSupportedOperationalProfiles().stream()
                            .map(OperationalProfile::name)
                            .filter(profileName -> profileName.equals(credentialVot))
                            .findFirst();

            // Successful match
            if (matchedOperationalProfile.isPresent()) {
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

    @Tracing
    private void sendProfileMatchedAuditEvent(
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser)
            throws SqsException {
        var auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionGpg45ProfileMatched(
                                gpg45Profile,
                                gpg45Scores,
                                VcHelper.extractTxnIdsFromCredentials(vcs)));
        auditService.sendAuditEvent(auditEvent);
    }
}
