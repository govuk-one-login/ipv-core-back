package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

public class CallTicfCriHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String VOT_P0 = "P0";
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final UserIdentityService userIdentityService;
    private final TicfCriService ticfCriService;
    private final CiMitService ciMitService;
    private final CiMitUtilityService ciMitUtilityService;
    private final CriStoringService criStoringService;
    private final VerifiableCredentialService verifiableCredentialService;

    @ExcludeFromGeneratedCoverageReport
    public CallTicfCriHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.ticfCriService = new TicfCriService(configService);
        this.ciMitService = new CiMitService(configService);
        this.ciMitUtilityService = new CiMitUtilityService(configService);
        this.criStoringService =
                new CriStoringService(
                        configService,
                        new AuditService(AuditService.getDefaultSqsClient(), configService),
                        null,
                        new VerifiableCredentialService(configService),
                        ciMitService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public CallTicfCriHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            UserIdentityService userIdentityService,
            TicfCriService ticfCriService,
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService,
            CriStoringService criStoringService,
            VerifiableCredentialService verifiableCredentialService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.userIdentityService = userIdentityService;
        this.ticfCriService = ticfCriService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
        this.criStoringService = criStoringService;
        this.verifiableCredentialService = verifiableCredentialService;
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
        LogHelper.attachCriIdToLogs(TICF_CRI);

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
                | ParseException
                | CiRetrievalException
                | ConfigException
                | JsonProcessingException e) {
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
            throws ParseException, TicfCriServiceException, CiRetrievalException, SqsException,
                    VerifiableCredentialException, CiPostMitigationsException, CiPutException,
                    JsonProcessingException, ConfigException {
        String featureSet = RequestHelper.getFeatureSet(request);
        configService.setFeatureSet(featureSet);
        ClientOAuthSessionItem clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());

        List<String> vcToSendToTicf =
                getVcToSendToTicf(clientOAuthSessionItem.getUserId(), ipvSessionItem);

        List<SignedJWT> ticfVcs =
                ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem, vcToSendToTicf);

        if (ticfVcs.isEmpty()) {
            LOGGER.warn(LogHelper.buildLogMessage("No TICF VC to process - returning next"));
            return JOURNEY_NEXT;
        }

        criStoringService.storeVcs(
                TICF_CRI, request.getIpAddress(), ticfVcs, clientOAuthSessionItem, ipvSessionItem);

        ContraIndicators cis =
                ciMitService.getContraIndicatorsVC(
                        clientOAuthSessionItem.getUserId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        request.getIpAddress());

        if (ciMitUtilityService.isBreachingCiThreshold(cis)) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "CI score is breaching threshold - setting VOT to P0"));
            ipvSessionItem.setVot(VOT_P0);

            return ciMitUtilityService
                    .getCiMitigationJourneyStep(cis)
                    .orElse(JOURNEY_FAIL_WITH_CI)
                    .toObjectMap();
        }

        LOGGER.info(LogHelper.buildLogMessage("CI score not breaching threshold"));
        return JOURNEY_NEXT;
    }

    @Tracing
    private List<String> getVcToSendToTicf(String userId, IpvSessionItem ipvSessionItem) {
        List<String> vcInStore =
                userIdentityService.getIdentityCredentials(
                        verifiableCredentialService.getVcStoreItems(userId));
        List<String> vcReceivedThisSession = ipvSessionItem.getVcReceivedThisSession();

        List<String> vcToSendToTicf = new ArrayList<>();
        if (vcReceivedThisSession != null) {
            vcToSendToTicf = vcInStore.stream().filter(vcReceivedThisSession::contains).toList();
        }

        return vcToSendToTicf;
    }
}
