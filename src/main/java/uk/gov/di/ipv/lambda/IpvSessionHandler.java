package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.service.IpvSessionService;

public class IpvSessionHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final IpvSessionService ipvSessionService;

    public IpvSessionHandler() {
        this.ipvSessionService = new IpvSessionService();
    }

    public IpvSessionHandler(IpvSessionService ipvSessionService) {
        this.ipvSessionService = ipvSessionService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        IpvSessionItem ipvSession = ipvSessionService.generateIpvSession();

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, ipvSession);
    }
}
