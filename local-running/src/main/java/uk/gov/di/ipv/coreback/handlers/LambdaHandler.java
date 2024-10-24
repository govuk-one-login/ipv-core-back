package uk.gov.di.ipv.coreback.handlers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import io.javalin.http.Context;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.BuildProvenUserIdentityDetailsHandler;
import uk.gov.di.ipv.core.builduseridentity.BuildUserIdentityHandler;
import uk.gov.di.ipv.core.initialiseipvsession.InitialiseIpvSessionHandler;
import uk.gov.di.ipv.core.issueclientaccesstoken.IssueClientAccessTokenHandler;
import uk.gov.di.ipv.core.processcricallback.ProcessCriCallbackHandler;
import uk.gov.di.ipv.core.processmobileappcallback.ProcessMobileAppCallbackHandler;
import uk.gov.di.ipv.core.userreverification.UserReverificationHandler;
import uk.gov.di.ipv.coreback.domain.CoreContext;

public class LambdaHandler {
    public static final CoreContext EMPTY_CONTEXT = new CoreContext();

    private final InitialiseIpvSessionHandler initialiseSessionHandler =
            new InitialiseIpvSessionHandler();
    private final BuildProvenUserIdentityDetailsHandler provenUserIdentityHandler =
            new BuildProvenUserIdentityDetailsHandler();
    private final ProcessCriCallbackHandler criCallbackHandler = new ProcessCriCallbackHandler();
    private final ProcessMobileAppCallbackHandler appCallbackHandler =
            new ProcessMobileAppCallbackHandler();
    private final IssueClientAccessTokenHandler tokenHandler = new IssueClientAccessTokenHandler();
    private final BuildUserIdentityHandler userIdentityHandler = new BuildUserIdentityHandler();
    private final UserReverificationHandler userReverificationHandler =
            new UserReverificationHandler();

    private void handleApiGatewayProxyRoute(
            Context ctx,
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler) {
        APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent = new APIGatewayProxyRequestEvent();
        apiGatewayProxyRequestEvent.setBody(ctx.body());
        apiGatewayProxyRequestEvent.setHeaders(ctx.headerMap());
        apiGatewayProxyRequestEvent.setPath(ctx.path());

        APIGatewayProxyResponseEvent responseEvent =
                handler.handleRequest(apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

        ctx.status(responseEvent.getStatusCode()).json(responseEvent.getBody());
    }

    public void initialiseSession(Context ctx) {
        handleApiGatewayProxyRoute(ctx, this.initialiseSessionHandler);
    }

    public void getProvenUserIdentityDetails(Context ctx) {
        handleApiGatewayProxyRoute(ctx, this.provenUserIdentityHandler);
    }

    public void getUserReverification(Context ctx) {
        handleApiGatewayProxyRoute(ctx, this.userReverificationHandler);
    }

    public void criCallback(Context ctx) {
        handleApiGatewayProxyRoute(ctx, this.criCallbackHandler);
    }

    public void appCallback(Context ctx) {
        handleApiGatewayProxyRoute(ctx, this.appCallbackHandler);
    }

    public void getToken(Context ctx) {
        handleApiGatewayProxyRoute(ctx, this.tokenHandler);
    }

    public void getUserIdentity(Context ctx) {
        handleApiGatewayProxyRoute(ctx, this.userIdentityHandler);
    }
}
