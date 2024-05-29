package uk.gov.di.ipv.coreback.handlers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.BuildProvenUserIdentityDetailsHandler;
import uk.gov.di.ipv.core.builduseridentity.BuildUserIdentityHandler;
import uk.gov.di.ipv.core.initialiseipvsession.InitialiseIpvSessionHandler;
import uk.gov.di.ipv.core.issueclientaccesstoken.IssueClientAccessTokenHandler;
import uk.gov.di.ipv.core.processcricallback.ProcessCriCallbackHandler;
import uk.gov.di.ipv.coreback.domain.CoreContext;

import java.util.HashMap;
import java.util.Map;

public class LambdaHandler {
    public static final CoreContext EMPTY_CONTEXT = new CoreContext();
    public static final String APPLICATION_JSON = "application/json";

    private final Route initialiseSession = apiGatewayProxyRoute(new InitialiseIpvSessionHandler());

    private final Route buildProvenUserIdentityDetails =
            apiGatewayProxyRoute(new BuildProvenUserIdentityDetailsHandler());

    private final Route criCallBack = apiGatewayProxyRoute(new ProcessCriCallbackHandler());

    private final Route token = apiGatewayProxyRoute(new IssueClientAccessTokenHandler());

    private final Route userIdentity = apiGatewayProxyRoute(new BuildUserIdentityHandler());

    private Route apiGatewayProxyRoute(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler) {
        return (Request request, Response response) -> {
            APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                    new APIGatewayProxyRequestEvent();
            apiGatewayProxyRequestEvent.setBody(request.body());
            apiGatewayProxyRequestEvent.setHeaders(getHeadersMap(request));
            apiGatewayProxyRequestEvent.setPath(request.pathInfo());

            APIGatewayProxyResponseEvent responseEvent =
                    handler.handleRequest(apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

            response.type(APPLICATION_JSON);
            return responseEvent.getBody();
        };
    }

    private Map<String, String> getHeadersMap(Request request) {
        Map<String, String> headers = new HashMap<>();
        request.headers().forEach(header -> headers.put(header, request.headers(header)));

        return headers;
    }

    public Route getInitialiseSession() {
        return this.initialiseSession;
    }

    public Route getBuildProvenUserIdentityDetails() {
        return this.buildProvenUserIdentityDetails;
    }

    public Route getCriCallBack() {
        return this.criCallBack;
    }

    public Route getToken() {
        return this.token;
    }

    public Route getUserIdentity() {
        return this.userIdentity;
    }
}
