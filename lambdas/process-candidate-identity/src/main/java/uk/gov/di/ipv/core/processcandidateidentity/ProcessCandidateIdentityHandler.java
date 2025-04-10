package uk.gov.di.ipv.core.processcandidateidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
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
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnknownProcessIdentityTypeException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
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
import uk.gov.di.ipv.core.processcandidateidentity.service.CheckCoiService;
import uk.gov.di.ipv.core.processcandidateidentity.service.StoreIdentityService;

import java.io.UncheckedIOException;
import java.text.ParseException;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.lang.Boolean.TRUE;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
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
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PROFILE_UNMET_PATH;

public class ProcessCandidateIdentityHandler
        implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private static final JourneyResponse JOURNEY_PROFILE_UNMET =
            new JourneyResponse(JOURNEY_PROFILE_UNMET_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final Map<String, Object> JOURNEY_COI_CHECK_FAILED =
            new JourneyResponse(JOURNEY_COI_CHECK_FAILED_PATH).toObjectMap();
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);

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

    // Candidate identities that should be subject to a COI check
    private static final Set<CandidateIdentityType> COI_CHECK_TYPES =
            EnumSet.of(NEW, PENDING, REVERIFICATION, UPDATE);

    // Candidate identities that should store the given identity (if successful)
    private static final Set<CandidateIdentityType> STORE_IDENTITY_TYPES =
            EnumSet.of(NEW, PENDING, UPDATE);

    // Candidate identities that should match a profile
    private static final Set<CandidateIdentityType> PROFILE_MATCHING_TYPES =
            EnumSet.of(NEW, UPDATE, EXISTING);

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
            TicfCriService ticfCriService) {
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
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
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
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to parse existing credentials", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse issued credentials", e));
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
            throws EvcsServiceException, HttpResponseExceptionWithErrorBody,
                    CredentialParseException, ParseException, CiExtractionException {
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
                            deviceInformation,
                            sessionVcs,
                            auditEventUser);

            if (!isCoiCheckSuccessful) {
                return JOURNEY_COI_CHECK_FAILED;
            }
        }

        if (PROFILE_MATCHING_TYPES.contains(processIdentityType)) {
            LOGGER.info(LogHelper.buildLogMessage("Performing profile evaluation"));
            var journey =
                    getJourneyResponseForProfileMatching(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            deviceInformation,
                            sessionVcs,
                            auditEventUser);

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
                            deviceInformation,
                            ipAddress,
                            auditEventUser);

            if (journey != null) {
                // We still store a pending identity - it might be mitigating an existing CI
                if (PENDING.equals(processIdentityType)) {
                    LOGGER.info(LogHelper.buildLogMessage("Storing identity"));
                    storeIdentityService.storeIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            processIdentityType,
                            deviceInformation,
                            sessionVcs,
                            auditEventUser);
                }
                return journey.toObjectMap();
            }
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }

        if (STORE_IDENTITY_TYPES.contains(processIdentityType)) {
            LOGGER.info(LogHelper.buildLogMessage("Storing identity"));
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    processIdentityType,
                    deviceInformation,
                    sessionVcs,
                    auditEventUser);
        }

        return JOURNEY_NEXT.toObjectMap();
    }

    private JourneyResponse getJourneyResponseForProfileMatching(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            List<VerifiableCredential> sessionVcs,
            AuditEventUser auditEventUser)
            throws HttpResponseExceptionWithErrorBody, ParseException, CredentialParseException,
                    CiExtractionException {
        if (StringUtils.isBlank(ipvSessionItem.getSecurityCheckCredential())) {
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    MISSING_SECURITY_CHECK_CREDENTIAL);
        }

        var areVcsCorrelated = userIdentityService.areVcsCorrelated(sessionVcs);

        if (!areVcsCorrelated) {
            return JOURNEY_VCS_NOT_CORRELATED;
        }

        var contraIndicators =
                cimitUtilityService.getContraIndicatorsFromVc(
                        ipvSessionItem.getSecurityCheckCredential(),
                        clientOAuthSessionItem.getUserId());

        var votResult =
                votMatcher.matchFirstVot(
                        VotHelper.getVotsByStrengthDescending(clientOAuthSessionItem),
                        sessionVcs,
                        contraIndicators,
                        areVcsCorrelated);

        if (votResult.isEmpty()) {
            return JOURNEY_PROFILE_UNMET;
        }

        ipvSessionItem.setVot(votResult.get().vot());
        ipvSessionService.updateIpvSession(ipvSessionItem);

        if (votResult.get().vot().getProfileType() == ProfileType.GPG45) {
            sendProfileMatchedAuditEvent(
                    votResult.get(),
                    VcHelper.filterVCBasedOnProfileType(sessionVcs, ProfileType.GPG45),
                    auditEventUser,
                    deviceInformation);
        }

        return null;
    }

    public JourneyResponse getJourneyResponseFromTicfCall(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress,
            AuditEventUser auditEventUser) {
        try {
            var ticfVcs = ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem);

            if (ticfVcs.isEmpty()) {
                LOGGER.warn(LogHelper.buildLogMessage("No TICF VC to process - returning next"));
                return null;
            }

            criStoringService.storeVcs(
                    TICF,
                    ipAddress,
                    deviceInformation,
                    ticfVcs,
                    clientOAuthSessionItem,
                    ipvSessionItem,
                    List.of(),
                    auditEventUser);

            if (!clientOAuthSessionItem.isReverification()) {
                // Get mitigations from old CIMIT VC to compare against the mitigations on the new
                // CIs
                var targetVot = VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem);
                var oldMitigations =
                        cimitUtilityService.getMitigationEventIfBreachingOrActive(
                                ipvSessionItem.getSecurityCheckCredential(),
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
                | UnrecognisedVotException
                | CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error processing response from TICF CRI", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ERROR_PROCESSING_TICF_CRI_RESPONSE);
        }
    }

    private void sendProfileMatchedAuditEvent(
            VotMatchingResult votMatchingResult,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        var auditEvent =
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionGpg45ProfileMatched(
                                votMatchingResult.gpg45Profile(),
                                votMatchingResult.gpg45Scores(),
                                VcHelper.extractTxnIdsFromCredentials(vcs)),
                        new AuditRestrictedDeviceInformation(deviceInformation));
        auditService.sendAuditEvent(auditEvent);
    }
}
