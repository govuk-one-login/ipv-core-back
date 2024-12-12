package uk.gov.di.ipv.core.processcandidateidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.ProcessIdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.*;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.*;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.processcandidateidentity.service.*;
import uk.gov.di.model.ContraIndicator;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.*;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.*;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.*;

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

    private static final Set<ProcessIdentityType> COI_CHECK_TYPES =
            EnumSet.of(
                    ProcessIdentityType.NEW,
                    ProcessIdentityType.PENDING,
                    ProcessIdentityType.REVERIFICATION);

    private static final Set<ProcessIdentityType> STORE_IDENTITY_TYPES =
            EnumSet.of(ProcessIdentityType.NEW, ProcessIdentityType.PENDING);

    private static final Set<ProcessIdentityType> GPG_45_TYPES =
            EnumSet.of(ProcessIdentityType.NEW);

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

            var coiCheckType = RequestHelper.getCoiCheckType(request);
            var identityType = RequestHelper.getIdentityType(request);

            String userId = clientOAuthSessionItem.getUserId();
            var sessionVcs =
                    sessionCredentialsService.getCredentials(
                            ipvSessionItem.getIpvSessionId(), userId);

            if (COI_CHECK_TYPES.contains(processIdentityType)) {
                var isCoiCheckSuccessful =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                coiCheckType,
                                deviceInformation,
                                ipAddress,
                                sessionVcs);

                if (!isCoiCheckSuccessful) {
                    return JOURNEY_COI_CHECK_FAILED;
                }
            }

            if (STORE_IDENTITY_TYPES.contains(processIdentityType)) {
                storeIdentityService.storeIdentity(
                        ipvSessionItem,
                        clientOAuthSessionItem,
                        identityType,
                        deviceInformation,
                        ipAddress,
                        sessionVcs);
            }

            if (GPG_45_TYPES.contains(processIdentityType)) {
                var journey =
                        getJourneyResponseFromGpg45ScoreEvaluation(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                deviceInformation,
                                ipAddress,
                                sessionVcs);

                if (!JOURNEY_NEXT.equals(journey)) {
                    return journey.toObjectMap();
                }
            }

            if (configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId())) {
                return this.getJourneyResponseFromTicfCall(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                deviceInformation,
                                ipAddress)
                        .toObjectMap();
            }

            return JOURNEY_NEXT.toObjectMap();

        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to process identity", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (UnknownProcessIdentityType e) {
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
        } catch (UnknownCoiCheckTypeException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Unknown COI check type received", e)
                            .with(LOG_CHECK_TYPE.getFieldName(), e.getCheckType()));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_INTERNAL_SERVER_ERROR, UNKNOWN_CHECK_TYPE)
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
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            if (ipvSessionItem != null) {
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }
            auditService.awaitAuditEvents();
        }
    }

    private JourneyResponse getJourneyResponseFromGpg45ScoreEvaluation(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress,
            List<VerifiableCredential> sessionVcs)
            throws HttpResponseExceptionWithErrorBody, CiRetrievalException {

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
                        ipvSessionItem,
                        clientOAuthSessionItem,
                        ipAddress,
                        deviceInformation,
                        contraIndicators);

        if (matchingGpg45Profile.isEmpty()) {
            logLambdaResponse("No GPG45 profiles have been met", JOURNEY_GPG45_UNMET);
            return JOURNEY_GPG45_UNMET;
        }

        ipvSessionItem.setVot(Vot.fromGpg45Profile(matchingGpg45Profile.get()));
        logLambdaResponse("A GPG45 profile has been met", JOURNEY_NEXT);

        return JOURNEY_NEXT;
    }

    public JourneyResponse getJourneyResponseFromTicfCall(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress) {
        try {
            var ticfVcs = ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem);

            if (ticfVcs.isEmpty()) {
                LOGGER.warn(LogHelper.buildLogMessage("No TICF VC to process - returning next"));
                return JOURNEY_NEXT;
            }

            criStoringService.storeVcs(
                    TICF,
                    ipAddress,
                    deviceInformation,
                    ticfVcs,
                    clientOAuthSessionItem,
                    ipvSessionItem,
                    List.of());

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

                return journeyResponse.get();
            }

            LOGGER.info(LogHelper.buildLogMessage("CI score not breaching threshold"));
            return JOURNEY_NEXT;
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

    private void logLambdaResponse(String lambdaResult, JourneyResponse journeyResponse) {
        var message =
                new StringMapMessage()
                        .with(LOG_LAMBDA_RESULT.getFieldName(), lambdaResult)
                        .with(LOG_JOURNEY_RESPONSE.getFieldName(), journeyResponse);
        LOGGER.info(message);
    }
}
