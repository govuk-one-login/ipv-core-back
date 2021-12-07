package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.service.IpvSessionService;

import java.util.Map;

public class IpvSessionHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String IPV_SESSION_ID_KEY = "ipvSessionId";

    private final IpvSessionService ipvSessionService;

    public IpvSessionHandler() {
        this.ipvSessionService = new IpvSessionService();
    }

    public IpvSessionHandler(IpvSessionService ipvSessionService) {
        this.ipvSessionService = ipvSessionService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        String ipvSessionId = ipvSessionService.generateIpvSession();

        Map<String, String> response = Map.of(IPV_SESSION_ID_KEY, ipvSessionId);

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
    }
}
