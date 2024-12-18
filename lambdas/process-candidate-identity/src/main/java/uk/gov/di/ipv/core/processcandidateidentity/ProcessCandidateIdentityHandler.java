package uk.gov.di.ipv.core.processcandidateidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.*;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.ticfcriservice.TicfCriService;
import uk.gov.di.ipv.core.library.ticfcriservice.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.service.CheckCoiService;
import uk.gov.di.ipv.core.processcandidateidentity.service.EvaluateGpg45ScoresService;
import uk.gov.di.ipv.core.processcandidateidentity.service.StoreIdentityService;
import uk.gov.di.model.AddressCredential;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.IdentityCheckCredential;

import java.text.ParseException;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.lang.Boolean.TRUE;
import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_STORED_CIS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.enums.CandidateIdentityType.REVERIFICATION;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_GPG45_UNMET_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

public class ProcessCandidateIdentityHandler
        implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private static final JourneyResponse JOURNEY_GPG45_UNMET =
            new JourneyResponse(JOURNEY_GPG45_UNMET_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final Map<String, Object> JOURNEY_COI_CHECK_FAILED =
            new JourneyResponse(JOURNEY_COI_CHECK_FAILED_PATH).toObjectMap();

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
    private final EvaluateGpg45ScoresService evaluateGpg45ScoresService;
    private final TicfCriService ticfCriService;
    private final CimitUtilityService cimitUtilityService;

    private static final Set<CandidateIdentityType> COI_CHECK_TYPES =
            EnumSet.of(
                    CandidateIdentityType.NEW,
                    CandidateIdentityType.PENDING,
                    REVERIFICATION,
                    CandidateIdentityType.UPDATE);

    private static final Set<CandidateIdentityType> STORE_IDENTITY_TYPES =
            EnumSet.of(
                    CandidateIdentityType.NEW,
                    CandidateIdentityType.PENDING,
                    CandidateIdentityType.UPDATE);

    private static final Set<CandidateIdentityType> GPG_45_TYPES =
            EnumSet.of(CandidateIdentityType.NEW, CandidateIdentityType.UPDATE);

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
        this.evaluateGpg45ScoresService =
                new EvaluateGpg45ScoresService(configService, auditService);
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
            EvaluateGpg45ScoresService evaluateGpg45ScoresService,
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
        this.evaluateGpg45ScoresService = evaluateGpg45ScoresService;
        this.storeIdentityService = storeIdentityService;
        this.ticfCriService = ticfCriService;
        this.cimitUtilityService = cimitUtilityService;
    }

    @Override
    @Tracing
    @Logging
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        LogHelper.attachComponentId(configService);
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));

        IpvSessionItem ipvSessionItem = null;
        try {
            var ipvSessionId = RequestHelper.getIpvSessionId(request);
            var ipAddress = RequestHelper.getIpAddress(request);
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
            LOGGER.error(LogHelper.buildErrorMessage("Failed to process identity", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (UnknownProcessIdentityTypeException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unknown process identity type", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_BAD_REQUEST,
                            UNEXPECTED_PROCESS_IDENTITY_TYPE)
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to find ipv session", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
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
                            SC_INTERNAL_SERVER_ERROR,
                            FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (CiRetrievalException e) {
            LOGGER.error(LogHelper.buildErrorMessage(FAILED_TO_GET_STORED_CIS.getMessage(), e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            FAILED_TO_GET_STORED_CIS)
                    .toObjectMap();
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to get VOT from operational VC", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
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

    private boolean isUpdateAddressJourney(
            CandidateIdentityType identityType, List<VerifiableCredential> sessionVcs) {
        if (!CandidateIdentityType.UPDATE.equals(identityType)) {
            return false;
        }

        // Check if the session VCs do not contain an IdentityCheckCredential and contains an
        // AddressCredential
        return sessionVcs.stream()
                        .noneMatch(vc -> vc.getCredential() instanceof IdentityCheckCredential)
                && sessionVcs.stream()
                        .anyMatch(vc -> vc.getCredential() instanceof AddressCredential);
    }

    private Map<String, Object> processCandidateThroughJourney(
            CandidateIdentityType processIdentityType,
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress,
            List<VerifiableCredential> sessionVcs,
            AuditEventUser auditEventUser)
            throws EvcsServiceException, HttpResponseExceptionWithErrorBody, CiRetrievalException,
                    CredentialParseException, ParseException {
        if (COI_CHECK_TYPES.contains(processIdentityType)
                && !isUpdateAddressJourney(processIdentityType, sessionVcs)) {
            var coiCheckType = getCoiCheckType(processIdentityType, clientOAuthSessionItem);
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

        if (STORE_IDENTITY_TYPES.contains(processIdentityType)) {
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    processIdentityType,
                    deviceInformation,
                    sessionVcs,
                    auditEventUser);
        }

        if (GPG_45_TYPES.contains(processIdentityType)) {
            var journey =
                    getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            deviceInformation,
                            ipAddress,
                            sessionVcs,
                            auditEventUser);

            if (journey != null) {
                return journey.toObjectMap();
            }
        }

        if (configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId())) {
            var journey =
                    getJourneyResponseFromTicfCall(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            deviceInformation,
                            ipAddress,
                            auditEventUser);

            if (journey != null) {
                return journey.toObjectMap();
            }
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }

        return JOURNEY_NEXT.toObjectMap();
    }

    private JourneyResponse getJourneyResponseFromGpg45ScoreEvaluation(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress,
            List<VerifiableCredential> sessionVcs,
            AuditEventUser auditEventUser)
            throws HttpResponseExceptionWithErrorBody, CiRetrievalException, ParseException {

        if (!userIdentityService.areVcsCorrelated(sessionVcs)) {
            return JOURNEY_VCS_NOT_CORRELATED;
        }

        // This is a performance optimisation as calling cimitService.getContraIndicators()
        // takes about 0.5 seconds.
        // If the VTR only contains one entry then it is impossible for a user to reach here
        // with a breaching CI so we don't have to check.
        var contraIndicators =
                clientOAuthSessionItem.getVtr().size() == 1
                        ? null
                        : cimitService.getContraIndicators(
                                clientOAuthSessionItem.getUserId(),
                                clientOAuthSessionItem.getGovukSigninJourneyId(),
                                ipAddress);

        var matchingGpg45Profile =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        sessionVcs,
                        clientOAuthSessionItem,
                        deviceInformation,
                        contraIndicators,
                        auditEventUser);

        if (matchingGpg45Profile.isEmpty()) {
            LOGGER.info(LogHelper.buildLogMessage("No GPG45 profiles have been met"));
            return JOURNEY_GPG45_UNMET;
        }

        ipvSessionItem.setVot(Vot.fromGpg45Profile(matchingGpg45Profile.get()));
        ipvSessionService.updateIpvSession(ipvSessionItem);
        LOGGER.info(LogHelper.buildLogMessage("A GPG45 profile has been met"));

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

            List<ContraIndicator> cis =
                    cimitService.getContraIndicators(
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            ipAddress);

            var thresholdVot = ipvSessionItem.getThresholdVot();

            var journeyResponse =
                    cimitUtilityService.getMitigationJourneyIfBreaching(cis, thresholdVot);
            if (journeyResponse.isPresent()) {
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "CI score is breaching threshold - setting VOT to P0"));
                ipvSessionItem.setVot(Vot.P0);
                ipvSessionService.updateIpvSession(ipvSessionItem);

                return journeyResponse.get();
            }

            LOGGER.info(LogHelper.buildLogMessage("CI score not breaching threshold"));

            return null;
        } catch (TicfCriServiceException
                | VerifiableCredentialException
                | CiPostMitigationsException
                | CiPutException
                | CiRetrievalException
                | ConfigException
                | UnrecognisedVotException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error processing response from TICF CRI", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ERROR_PROCESSING_TICF_CRI_RESPONSE);
        }
    }
}
