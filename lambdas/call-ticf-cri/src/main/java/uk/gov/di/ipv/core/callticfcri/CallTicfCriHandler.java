package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.callticfcri.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.callticfcri.service.TicfCriService;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

public class CallTicfCriHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final TicfCriService ticfCriService;
    private final CiMitService ciMitService;
    private final CiMitUtilityService ciMitUtilityService;
    private final CriStoringService criStoringService;

    @ExcludeFromGeneratedCoverageReport
    public CallTicfCriHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ticfCriService = new TicfCriService(configService);
        this.ciMitService = new CiMitService(configService);
        this.ciMitUtilityService = new CiMitUtilityService(configService);
        this.criStoringService =
                new CriStoringService(
                        configService,
                        new AuditService(AuditService.getSqsClient(), configService),
                        null,
                        new SessionCredentialsService(configService),
                        ciMitService);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public CallTicfCriHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            TicfCriService ticfCriService,
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService,
            CriStoringService criStoringService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.ticfCriService = ticfCriService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
        this.criStoringService = criStoringService;
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        LogHelper.attachComponentId(configService);
        LogHelper.attachCriIdToLogs(TICF.getId());

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
                | SqsException
                | VerifiableCredentialException
                | CiPostMitigationsException
                | CiPutException
                | CiRetrievalException
                | ConfigException
                | UnrecognisedVotException
                | CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error processing response from TICF CRI", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ERROR_PROCESSING_TICF_CRI_RESPONSE)
                    .toObjectMap();
        } finally {
            if (ipvSessionItem != null) {
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }
        }
    }

    @Tracing
    private Map<String, Object> callTicfCri(IpvSessionItem ipvSessionItem, ProcessRequest request)
            throws TicfCriServiceException, CiRetrievalException, SqsException,
                    VerifiableCredentialException, CiPostMitigationsException, CiPutException,
                    ConfigException, UnrecognisedVotException, CredentialParseException {
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));
        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        var vtr = clientOAuthSessionItem.getVtr();
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());

        var ticfVcs = ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem);

        if (ticfVcs.isEmpty()) {
            LOGGER.warn(LogHelper.buildLogMessage("No TICF VC to process - returning next"));
            return JOURNEY_NEXT;
        }

        criStoringService.storeVcs(
                TICF.getId(),
                request.getIpAddress(),
                request.getDeviceInformation(),
                ticfVcs,
                clientOAuthSessionItem,
                ipvSessionItem);

        ContraIndicators cis =
                ciMitService.getContraIndicators(
                        clientOAuthSessionItem.getUserId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        request.getIpAddress());

        var journeyResponse = ciMitUtilityService.checkCiLevel(cis, vtr);
        if (journeyResponse.isPresent()) {
            return journeyResponse.get().toObjectMap();
        }

        LOGGER.info(LogHelper.buildLogMessage("CI score not breaching threshold"));
        return JOURNEY_NEXT;
    }
}
