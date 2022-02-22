package uk.gov.di.ipv.core.session;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;

public class IpvSessionHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String IPV_SESSION_ID_KEY = "ipvSessionId";

    private final ConfigurationService configurationService;

    private final IpvSessionService ipvSessionService;

    @ExcludeFromGeneratedCoverageReport
    public IpvSessionHandler() {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    public IpvSessionHandler(
            IpvSessionService ipvSessionService, ConfigurationService configurationService) {
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        String ipvSessionId = ipvSessionService.generateIpvSession();

        Map<String, String> response = Map.of(IPV_SESSION_ID_KEY, ipvSessionId);

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
    }
}
