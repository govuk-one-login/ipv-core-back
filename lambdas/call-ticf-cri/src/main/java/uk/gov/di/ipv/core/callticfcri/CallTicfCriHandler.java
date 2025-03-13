package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.VotHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.ticf.TicfCriService;
import uk.gov.di.ipv.core.library.ticf.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

public class CallTicfCriHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final TicfCriService ticfCriService;
    private final CimitService cimitService;
    private final CimitUtilityService cimitUtilityService;
    private final CriStoringService criStoringService;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public CallTicfCriHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CallTicfCriHandler(ConfigService configService) {
        this.configService = configService;
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ticfCriService = new TicfCriService(configService);
        this.cimitService = new CimitService(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.auditService = AuditService.create(configService);
        this.criStoringService =
                new CriStoringService(
                        configService,
                        auditService,
                        null,
                        new SessionCredentialsService(configService),
                        cimitService);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public CallTicfCriHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            TicfCriService ticfCriService,
            CimitService cimitService,
            CimitUtilityService cimitUtilityService,
            CriStoringService criStoringService,
            AuditService auditService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.ticfCriService = ticfCriService;
        this.cimitService = cimitService;
        this.cimitUtilityService = cimitUtilityService;
        this.criStoringService = criStoringService;
        this.auditService = auditService;
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        LogHelper.attachComponentId(configService);
        LogHelper.attachCriIdToLogs(TICF);

        IpvSessionItem ipvSessionItem = null;
        try {
            ipvSessionItem =
                    ipvSessionService.getIpvSession(RequestHelper.getIpvSessionId(request));

            return callTicfCri(ipvSessionItem, request);

        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error calling TICF CRI", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (TicfCriServiceException
                | VerifiableCredentialException
                | CiPostMitigationsException
                | CiPutException
                | CiRetrievalException
                | ConfigException
                | UnrecognisedVotException
                | IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error processing response from TICF CRI", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            ERROR_PROCESSING_TICF_CRI_RESPONSE)
                    .toObjectMap();
        } catch (CiExtractionException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(FAILED_TO_EXTRACT_CIS_FROM_VC.getMessage(), e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            FAILED_TO_EXTRACT_CIS_FROM_VC)
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

    private Map<String, Object> callTicfCri(IpvSessionItem ipvSessionItem, ProcessRequest request)
            throws TicfCriServiceException, CiRetrievalException, VerifiableCredentialException,
                    CiPostMitigationsException, CiPutException, ConfigException,
                    UnrecognisedVotException, HttpResponseExceptionWithErrorBody,
                    CiExtractionException {
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));
        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());

        var ticfVcs = ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem);

        if (ticfVcs.isEmpty()) {
            LOGGER.warn(LogHelper.buildLogMessage("No TICF VC to process - returning next"));
            return JOURNEY_NEXT;
        }

        criStoringService.storeVcs(
                TICF,
                request.getIpAddress(),
                request.getDeviceInformation(),
                ticfVcs,
                clientOAuthSessionItem,
                ipvSessionItem,
                List.of());

        if (!clientOAuthSessionItem.getScopeClaims().contains(REVERIFICATION)) {
            var contraIndicatorVc =
                    cimitService.getContraIndicatorsVc(
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            request.getIpAddress(),
                            ipvSessionItem);

            var cis = cimitUtilityService.getContraIndicatorsFromVc(contraIndicatorVc);

            var journeyResponse =
                    cimitUtilityService.getMitigationJourneyIfBreaching(
                            cis, VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem));
            if (journeyResponse.isPresent()) {
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "CI score is breaching threshold - setting VOT to P0"));
                ipvSessionItem.setVot(Vot.P0);

                return journeyResponse.get().toObjectMap();
            }
            LOGGER.info(LogHelper.buildLogMessage("CI score not breaching threshold"));
        }

        return JOURNEY_NEXT;
    }
}
