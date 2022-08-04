package uk.gov.di.ipv.core.selectcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.util.List;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;

public class SelectCriHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CRI_START_JOURNEY = "/journey/%s";
    public static final String JOURNEY_ERROR = "/journey/error";

    private final ConfigurationService configurationService;
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;

    public SelectCriHandler(
            ConfigurationService configurationService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService) {
        this.configurationService = configurationService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public SelectCriHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            String userId = ipvSessionService.getUserId(ipvSessionId);
            List<String> visitedCredentialIssuers =
                    userIdentityService.getUserIssuedCredentialIssuers(userId);

            String passportCriId = configurationService.getSsmParameter(PASSPORT_CRI_ID);
            String fraudCriId = configurationService.getSsmParameter(FRAUD_CRI_ID);
            String kbvCriId = configurationService.getSsmParameter(KBV_CRI_ID);
            String addressCriId = configurationService.getSsmParameter(KBV_CRI_ID);

            if (userHasNotVisited(visitedCredentialIssuers, passportCriId)) {
                return getJourneyResponse(passportCriId);
            }

            if (userHasNotVisited(visitedCredentialIssuers, addressCriId)) {
                return getJourneyResponse(addressCriId);
            }

            if (userHasNotVisited(visitedCredentialIssuers, fraudCriId)) {
                return getJourneyResponse(fraudCriId);
            }

            if (userHasNotVisited(visitedCredentialIssuers, kbvCriId)) {
                return getJourneyResponse(kbvCriId);
            }

            LOGGER.info("Unable to determine next credential issuer");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, new JourneyResponse(JOURNEY_ERROR));

        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }

    private APIGatewayProxyResponseEvent getJourneyResponse(String passportCriId) {
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatus.SC_OK,
                new JourneyResponse(String.format(CRI_START_JOURNEY, passportCriId)));
    }

    private boolean userHasNotVisited(List<String> visitedCredentialIssuers, String passportCriId) {
        return visitedCredentialIssuers.stream().noneMatch(passportCriId::equals);
    }
}
