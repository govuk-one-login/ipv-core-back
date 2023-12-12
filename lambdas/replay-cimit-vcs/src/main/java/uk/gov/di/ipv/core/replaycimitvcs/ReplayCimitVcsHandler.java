package uk.gov.di.ipv.core.replaycimitvcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;



public class ReplayCimitVcsHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final VerifiableCredentialService verifiableCredentialService;

    @SuppressWarnings("unused") // Used by AWS
    public ReplayCimitVcsHandler(
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            ConfigService configService,
            IpvSessionService ipvSessionService,
            VerifiableCredentialService verifiableCredentialService) {
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.verifiableCredentialService = verifiableCredentialService;
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public ReplayCimitVcsHandler() {
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService();
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest event, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
        try {
            String ipvSessionId = getIpvSessionId(event);
            String featureSet = RequestHelper.getFeatureSet(event);
            configService.setFeatureSet(featureSet);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String userId = clientOAuthSessionItem.getUserId();
            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("HTTP response exception", e);
        }
    }
}
