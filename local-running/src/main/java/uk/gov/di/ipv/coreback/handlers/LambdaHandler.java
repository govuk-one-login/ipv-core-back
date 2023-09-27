package uk.gov.di.ipv.coreback.handlers;

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
import uk.gov.di.ipv.core.checkciscore.CheckCiScoreHandler;
import uk.gov.di.ipv.core.checkexistingidentity.CheckExistingIdentityHandler;
import uk.gov.di.ipv.core.checkgpg45score.CheckGpg45ScoreHandler;
import uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler;
import uk.gov.di.ipv.core.initialiseipvsession.InitialiseIpvSessionHandler;
import uk.gov.di.ipv.core.issueclientaccesstoken.IssueClientAccessTokenHandler;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.JourneyError;
import uk.gov.di.ipv.core.processjourneyevent.ProcessJourneyEventHandler;
import uk.gov.di.ipv.core.resetidentity.ResetIdentityHandler;
import uk.gov.di.ipv.core.retrievecricredential.RetrieveCriCredentialHandler;
import uk.gov.di.ipv.core.retrievecrioauthaccesstoken.RetrieveCriOauthAccessTokenHandler;
import uk.gov.di.ipv.core.validateoauthcallback.ValidateOAuthCallbackHandler;
import uk.gov.di.ipv.core.validateoauthcallback.dto.CriCallbackRequest;
import uk.gov.di.ipv.coreback.domain.CoreContext;

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
    private CheckCiScoreHandler checkCiScoreHandler;
    private CheckGpg45ScoreHandler checkGpg45ScoreHandler;
    private BuildProvenUserIdentityDetailsHandler buildProvenUserIdentityDetailsHandler;
    private ValidateOAuthCallbackHandler validateOAuthCallbackHandler;
    private RetrieveCriOauthAccessTokenHandler retrieveCriOauthAccessTokenHandler;
    private RetrieveCriCredentialHandler retrieveCriCredentialHandler;
    private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;
    private IssueClientAccessTokenHandler issueClientAccessTokenHandler;
    private BuildUserIdentityHandler buildUserIdentityHandler;

    public LambdaHandler() throws IOException {
        this.initialiseIpvSessionHandler = new InitialiseIpvSessionHandler();
        this.processJourneyEventHandler = new ProcessJourneyEventHandler();
        this.checkExistingIdentityHandler = new CheckExistingIdentityHandler();
        this.resetIdentityHandler = new ResetIdentityHandler();
        this.buildCriOauthRequestHandler = new BuildCriOauthRequestHandler();
        this.buildClientOauthResponseHandler = new BuildClientOauthResponseHandler();
        this.checkCiScoreHandler = new CheckCiScoreHandler();
        this.checkGpg45ScoreHandler = new CheckGpg45ScoreHandler();
        this.buildProvenUserIdentityDetailsHandler = new BuildProvenUserIdentityDetailsHandler();
        this.validateOAuthCallbackHandler = new ValidateOAuthCallbackHandler();
        this.retrieveCriOauthAccessTokenHandler = new RetrieveCriOauthAccessTokenHandler();
        this.retrieveCriCredentialHandler = new RetrieveCriCredentialHandler();
        this.evaluateGpg45ScoresHandler = new EvaluateGpg45ScoresHandler();
        this.issueClientAccessTokenHandler = new IssueClientAccessTokenHandler();
        this.buildUserIdentityHandler = new BuildUserIdentityHandler();
    }

    private Route initialiseSession =
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

    private Route journeyEngine =
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

                    if ("/journey/check-existing-identity".equals(journey)) {
                        lambdaOutput =
                                checkExistingIdentityHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey(JOURNEY)) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get(JOURNEY);
                    } else if ("/journey/reset-identity".equals(journey)) {
                        lambdaOutput =
                                resetIdentityHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey(JOURNEY)) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get(JOURNEY);
                    } else if (journey != null
                            && journey.matches("/journey/cri/build-oauth-request/.*")) {
                        lambdaOutput =
                                buildCriOauthRequestHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey(JOURNEY)) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get(JOURNEY);
                    } else if ("/journey/build-client-oauth-response".equals(journey)) {
                        lambdaOutput =
                                buildClientOauthResponseHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey(JOURNEY)) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get(JOURNEY);
                    } else if ("/journey/ci-scoring".equals(journey)) {
                        lambdaOutput =
                                checkCiScoreHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey(JOURNEY)) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get(JOURNEY);
                    } else if ("/journey/check-gpg45-score".equals(journey)) {
                        ProcessRequest processRequest =
                                buildProcessRequest(request, processJourneyEventOutput);
                        lambdaOutput =
                                checkGpg45ScoreHandler.handleRequest(processRequest, EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey(JOURNEY)) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get(JOURNEY);
                    } else {
                        return gson.toJson(processJourneyEventOutput);
                    }
                }
            };

    private Route buildProvenUserIdentityDetails =
            (Request request, Response response) -> {
                Map<String, Object> lambdaOutput =
                        buildProvenUserIdentityDetailsHandler.handleRequest(
                                buildJourneyRequest(
                                        gson.fromJson(request.body(), MAP_STRING_STRING_TYPE),
                                        null),
                                EMPTY_CONTEXT);

                response.body(gson.toJson(lambdaOutput));
                return response;
            };

    private Route criCallBack =
            (Request request, Response response) -> {
                Map<String, Object> validateLambdaOutput =
                        validateOAuthCallbackHandler.handleRequest(
                                buildCriCallbackRequest(request), EMPTY_CONTEXT);

                if (!validateLambdaOutput.containsKey(JOURNEY)
                        || !"/journey/cri/access-token".equals(validateLambdaOutput.get(JOURNEY))) {
                    return gson.toJson(validateLambdaOutput);
                }

                try {
                    retrieveCriOauthAccessTokenHandler.handleRequest(
                            buildCriReturnLambdaInput(request), EMPTY_CONTEXT);
                } catch (JourneyError | IllegalArgumentException e) {
                    return "{\"journey\":\"/journey/error\"}";
                }

                Map<String, Object> retrieveCredLambdaOutput =
                        retrieveCriCredentialHandler.handleRequest(
                                buildCriReturnLambdaInput(request), EMPTY_CONTEXT);

                if (!retrieveCredLambdaOutput.containsKey(JOURNEY)
                        || !"/journey/ci-scoring".equals(retrieveCredLambdaOutput.get(JOURNEY))) {
                    return gson.toJson(retrieveCredLambdaOutput);
                }

                Map<String, Object> ciScoringLambdaOutput =
                        checkCiScoreHandler.handleRequest(
                                buildJourneyRequest(request, null), EMPTY_CONTEXT);

                if (!ciScoringLambdaOutput.containsKey(JOURNEY)
                        || !"/journey/ci-score-not-breaching"
                                .equals(ciScoringLambdaOutput.get(JOURNEY))) {
                    return gson.toJson(ciScoringLambdaOutput);
                }

                Map<String, Object> evaluateGpg45LambdaOutput =
                        evaluateGpg45ScoresHandler.handleRequest(
                                buildJourneyRequest(request, null), EMPTY_CONTEXT);

                return gson.toJson(evaluateGpg45LambdaOutput);
            };

    private Route token =
            (Request request, Response response) -> {
                APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                        new APIGatewayProxyRequestEvent();
                apiGatewayProxyRequestEvent.setBody(request.body());
                apiGatewayProxyRequestEvent.setHeaders(getHeadersMap(request));

                APIGatewayProxyResponseEvent responseEvent =
                        issueClientAccessTokenHandler.handleRequest(
                                apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

                response.type(APPLICATION_JSON);
                return responseEvent.getBody();
            };

    private Route userIdentity =
            (Request request, Response response) -> {
                APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                        new APIGatewayProxyRequestEvent();
                apiGatewayProxyRequestEvent.setBody(request.body());
                apiGatewayProxyRequestEvent.setHeaders(getHeadersMap(request));

                APIGatewayProxyResponseEvent responseEvent =
                        buildUserIdentityHandler.handleRequest(
                                apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

                response.type(APPLICATION_JSON);
                return responseEvent.getBody();
            };

    private JourneyRequest buildJourneyRequest(Request request, String journey) {
        return JourneyRequest.builder()
                .ipvSessionId(request.headers(IPV_SESSION_ID))
                .ipAddress(request.headers(IP_ADDRESS))
                .clientOAuthSessionId(request.headers(CLIENT_SESSION_ID))
                .featureSet(request.headers(FEATURE_SET))
                .journey(journey)
                .build();
    }

    private Map<String, String> buildCriReturnLambdaInput(Request request) {
        HashMap<String, String> nextLambdaInput = new HashMap<>();
        nextLambdaInput.put("ipvSessionId", request.headers(IPV_SESSION_ID));
        nextLambdaInput.put("ipAddress", request.headers(IP_ADDRESS));
        nextLambdaInput.put("featureSet", request.headers(FEATURE_SET));
        return nextLambdaInput;
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

    private CriCallbackRequest buildCriCallbackRequest(Request request) {
        Map<String, String> requestBody = gson.fromJson(request.body(), MAP_STRING_STRING_TYPE);
        return CriCallbackRequest.builder()
                .authorizationCode(requestBody.get("authorizationCode"))
                .credentialIssuerId(requestBody.get("credentialIssuerId"))
                .ipvSessionId(request.headers(IPV_SESSION_ID))
                .redirectUri(requestBody.get("redirectUri"))
                .state(requestBody.get("state"))
                .error(requestBody.get("error"))
                .errorDescription(requestBody.get("errorDescription"))
                .ipAddress(request.headers(IP_ADDRESS))
                .featureSet(request.headers(FEATURE_SET))
                .build();
    }

    private ProcessRequest buildProcessRequest(
            Request request, Map<String, Object> processJourneyEventOutput) {
        Map<String, Object> lambdaInput =
                (Map<String, Object>) processJourneyEventOutput.get("lambdaInput");
        return ProcessRequest.processRequestBuilder()
                .ipvSessionId(request.headers(IPV_SESSION_ID))
                .ipAddress(request.headers(IP_ADDRESS))
                .clientOAuthSessionId(request.headers(CLIENT_SESSION_ID))
                .featureSet(request.headers(FEATURE_SET))
                .journey((String) processJourneyEventOutput.get(JOURNEY))
                .scoreType((String) lambdaInput.get("scoreType"))
                .scoreThreshold((int) lambdaInput.get("scoreThreshold"))
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
