package uk.gov.di.ipv.coreback.handlers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.core.buildclientoauthresponse.BuildClientOauthResponseHandler;
import uk.gov.di.ipv.core.buildcrioauthrequest.BuildCriOauthRequestHandler;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.BuildProvenUserIdentityDetailsHandler;
import uk.gov.di.ipv.core.builduseridentity.BuildUserIdentityHandler;
import uk.gov.di.ipv.core.callticfcri.CallTicfCriHandler;
import uk.gov.di.ipv.core.checkexistingidentity.CheckExistingIdentityHandler;
import uk.gov.di.ipv.core.checkgpg45score.CheckGpg45ScoreHandler;
import uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler;
import uk.gov.di.ipv.core.initialiseipvsession.InitialiseIpvSessionHandler;
import uk.gov.di.ipv.core.issueclientaccesstoken.IssueClientAccessTokenHandler;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.processcricallback.ProcessCriCallbackHandler;
import uk.gov.di.ipv.core.processjourneyevent.ProcessJourneyEventHandler;
import uk.gov.di.ipv.core.resetidentity.ResetIdentityHandler;
import uk.gov.di.ipv.coreback.domain.CoreContext;
import uk.gov.di.ipv.coreback.exceptions.UnrecognisedJourneyException;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

public class LambdaHandler {

    private static final Gson gson = new Gson();
    public static final CoreContext EMPTY_CONTEXT = new CoreContext();
    public static final Type MAP_STRING_STRING_TYPE =
            new TypeToken<Map<String, String>>() {}.getType();
    public static final String APPLICATION_JSON = "application/json";
    public static final String JOURNEY = "journey";
    public static final String IPV_SESSION_ID = "ipv-session-id";
    public static final String IP_ADDRESS = "ip-address";
    public static final String CLIENT_SESSION_ID = "client-session-id";
    public static final String FEATURE_SET = "feature-set";

    private InitialiseIpvSessionHandler initialiseIpvSessionHandler;
    private ProcessJourneyEventHandler processJourneyEventHandler;
    private CheckExistingIdentityHandler checkExistingIdentityHandler;
    private ResetIdentityHandler resetIdentityHandler;
    private BuildCriOauthRequestHandler buildCriOauthRequestHandler;
    private BuildClientOauthResponseHandler buildClientOauthResponseHandler;
    private CheckGpg45ScoreHandler checkGpg45ScoreHandler;
    private BuildProvenUserIdentityDetailsHandler buildProvenUserIdentityDetailsHandler;
    private ProcessCriCallbackHandler processCriCallbackHandler;
    private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;
    private IssueClientAccessTokenHandler issueClientAccessTokenHandler;
    private BuildUserIdentityHandler buildUserIdentityHandler;
    private CallTicfCriHandler callTicfCriHandler;

    public LambdaHandler() throws IOException {
        this.initialiseIpvSessionHandler = new InitialiseIpvSessionHandler();
        this.processJourneyEventHandler = new ProcessJourneyEventHandler();
        this.checkExistingIdentityHandler = new CheckExistingIdentityHandler();
        this.resetIdentityHandler = new ResetIdentityHandler();
        this.buildCriOauthRequestHandler = new BuildCriOauthRequestHandler();
        this.buildClientOauthResponseHandler = new BuildClientOauthResponseHandler();
        this.checkGpg45ScoreHandler = new CheckGpg45ScoreHandler();
        this.buildProvenUserIdentityDetailsHandler = new BuildProvenUserIdentityDetailsHandler();
        this.processCriCallbackHandler = new ProcessCriCallbackHandler();
        this.evaluateGpg45ScoresHandler = new EvaluateGpg45ScoresHandler();
        this.issueClientAccessTokenHandler = new IssueClientAccessTokenHandler();
        this.buildUserIdentityHandler = new BuildUserIdentityHandler();
        this.callTicfCriHandler = new CallTicfCriHandler();
    }

    private final Route initialiseSession =
            (Request request, Response response) -> {
                APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                        new APIGatewayProxyRequestEvent();
                apiGatewayProxyRequestEvent.setBody(request.body());
                apiGatewayProxyRequestEvent.setHeaders(getHeadersMap(request));

                APIGatewayProxyResponseEvent responseEvent =
                        initialiseIpvSessionHandler.handleRequest(
                                apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

                response.type(APPLICATION_JSON);
                return responseEvent.getBody();
            };

    private final Route journeyEngine =
            (Request request, Response response) -> {
                String journey = request.pathInfo();

                Map<String, Object> lambdaOutput;
                Map<String, Object> processJourneyEventOutput;
                while (true) {
                    processJourneyEventOutput =
                            processJourneyEventHandler.handleRequest(
                                    buildProcessJourneyEventLambdaInput(request, journey),
                                    EMPTY_CONTEXT);

                    journey = (String) processJourneyEventOutput.get(JOURNEY);

                    if (journey == null) {
                        return gson.toJson(processJourneyEventOutput);
                    }

                    switch (journey) {
                        case "/journey/check-existing-identity":
                            lambdaOutput =
                                    checkExistingIdentityHandler.handleRequest(
                                            buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                            break;
                        case "/journey/reset-identity":
                            lambdaOutput =
                                    resetIdentityHandler.handleRequest(
                                            buildProcessRequest(request, processJourneyEventOutput),
                                            EMPTY_CONTEXT);
                            break;
                        case "/journey/build-client-oauth-response":
                            lambdaOutput =
                                    buildClientOauthResponseHandler.handleRequest(
                                            buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                            break;
                        case "/journey/evaluate-gpg45-scores":
                            lambdaOutput =
                                    evaluateGpg45ScoresHandler.handleRequest(
                                            buildProcessRequest(request, processJourneyEventOutput),
                                            EMPTY_CONTEXT);
                            break;
                        case "/journey/check-gpg45-scores":
                            lambdaOutput =
                                    checkGpg45ScoreHandler.handleRequest(
                                            buildProcessRequest(request, processJourneyEventOutput),
                                            EMPTY_CONTEXT);
                            break;
                        case "/journey/call-ticf-cri":
                            lambdaOutput =
                                    callTicfCriHandler.handleRequest(
                                            buildProcessRequest(request, processJourneyEventOutput),
                                            EMPTY_CONTEXT);
                            break;
                        default:
                            if (journey.matches("/journey/cri/build-oauth-request/.*")) {
                                lambdaOutput =
                                        buildCriOauthRequestHandler.handleRequest(
                                                buildJourneyRequest(request, journey),
                                                EMPTY_CONTEXT);
                            } else {
                                throw new UnrecognisedJourneyException(
                                        String.format("Journey not configured: %s", journey));
                            }
                    }
                    if (!lambdaOutput.containsKey(JOURNEY)) {
                        return gson.toJson(lambdaOutput);
                    }
                    journey = (String) lambdaOutput.get(JOURNEY);
                }
            };

    private final Route buildProvenUserIdentityDetails =
            (Request request, Response response) -> {
                Map<String, Object> lambdaOutput =
                        buildProvenUserIdentityDetailsHandler.handleRequest(
                                buildJourneyRequest(request, null), EMPTY_CONTEXT);

                return gson.toJson(lambdaOutput);
            };

    private final Route criCallBack =
            (Request request, Response response) ->
                    callExternalApiLambda(request, response, processCriCallbackHandler);

    private final Route token =
            (Request request, Response response) ->
                    callExternalApiLambda(request, response, issueClientAccessTokenHandler);

    private final Route userIdentity =
            (Request request, Response response) ->
                    callExternalApiLambda(request, response, buildUserIdentityHandler);

    private String callExternalApiLambda(
            Request request,
            Response response,
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler) {
        APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent = new APIGatewayProxyRequestEvent();
        apiGatewayProxyRequestEvent.setBody(request.body());
        apiGatewayProxyRequestEvent.setHeaders(getHeadersMap(request));

        APIGatewayProxyResponseEvent responseEvent =
                handler.handleRequest(apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

        response.type(APPLICATION_JSON);
        return responseEvent.getBody();
    }

    private JourneyRequest buildJourneyRequest(Request request, String journey) {
        return JourneyRequest.builder()
                .ipvSessionId(request.headers(IPV_SESSION_ID))
                .ipAddress(request.headers(IP_ADDRESS))
                .clientOAuthSessionId(request.headers(CLIENT_SESSION_ID))
                .featureSet(request.headers(FEATURE_SET))
                .journey(journey)
                .build();
    }

    private Map<String, String> getHeadersMap(Request request) {
        Map<String, String> headers = new HashMap<>();
        request.headers().forEach(header -> headers.put(header, request.headers(header)));

        return headers;
    }

    private Map<String, String> buildProcessJourneyEventLambdaInput(
            Request request, String journey) {
        return gson.fromJson(
                gson.toJson(buildJourneyRequest(request, journey)), MAP_STRING_STRING_TYPE);
    }

    private ProcessRequest buildProcessRequest(
            Request request, Map<String, Object> processJourneyEventOutput) {
        return ProcessRequest.processRequestBuilder()
                .ipvSessionId(request.headers(IPV_SESSION_ID))
                .ipAddress(request.headers(IP_ADDRESS))
                .clientOAuthSessionId(request.headers(CLIENT_SESSION_ID))
                .featureSet(request.headers(FEATURE_SET))
                .journey((String) processJourneyEventOutput.get(JOURNEY))
                .lambdaInput((Map<String, Object>) processJourneyEventOutput.get("lambdaInput"))
                .build();
    }

    public Route getInitialiseSession() {
        return this.initialiseSession;
    }

    public Route getJourneyEngine() {
        return this.journeyEngine;
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
