package uk.gov.di.ipv.coreback.handlers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.core.buildclientoauthresponse.BuildClientOauthResponseHandler;
import uk.gov.di.ipv.core.buildcrioauthrequest.BuildCriOauthRequestHandler;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.BuildProvenUserIdentityDetailsHandler;
import uk.gov.di.ipv.core.builduseridentity.BuildUserIdentityHandler;
import uk.gov.di.ipv.core.checkexistingidentity.CheckExistingIdentityHandler;
import uk.gov.di.ipv.core.checkgpg45score.CheckGpg45ScoreHandler;
import uk.gov.di.ipv.core.ciscoring.CiScoringHandler;
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
    private static final Logger LOGGER = LoggerFactory.getLogger(LambdaHandler.class);
    public static final Type MAP_STRING_STRING_TYPE =
            new TypeToken<Map<String, String>>() {}.getType();
    public static final String APPLICATION_JSON = "application/json";

    private InitialiseIpvSessionHandler initialiseIpvSessionHandler;
    private ProcessJourneyEventHandler processJourneyEventHandler;
    private CheckExistingIdentityHandler checkExistingIdentityHandler;
    private ResetIdentityHandler resetIdentityHandler;
    private BuildCriOauthRequestHandler buildCriOauthRequestHandler;
    private BuildClientOauthResponseHandler buildClientOauthResponseHandler;
    private CiScoringHandler ciScoringHandler;
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
        this.ciScoringHandler = new CiScoringHandler();
        this.checkGpg45ScoreHandler = new CheckGpg45ScoreHandler();
        this.buildProvenUserIdentityDetailsHandler = new BuildProvenUserIdentityDetailsHandler();
        this.validateOAuthCallbackHandler = new ValidateOAuthCallbackHandler();
        this.retrieveCriOauthAccessTokenHandler = new RetrieveCriOauthAccessTokenHandler();
        this.retrieveCriCredentialHandler = new RetrieveCriCredentialHandler();
        this.evaluateGpg45ScoresHandler = new EvaluateGpg45ScoresHandler();
        this.issueClientAccessTokenHandler = new IssueClientAccessTokenHandler();
        this.buildUserIdentityHandler = new BuildUserIdentityHandler();
    }

    public Route initialiseSession =
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

    public Route journeyEngine =
            (Request request, Response response) -> {
                String journey = request.pathInfo();

                Map<String, Object> lambdaOutput = new HashMap<>();
                Map<String, Object> processJourneyEventOutput;
                while (true) {
                    processJourneyEventOutput =
                            processJourneyEventHandler.handleRequest(
                                    buildProcessJourneyEventLambdaInput(request, journey),
                                    EMPTY_CONTEXT);

                    journey = (String) processJourneyEventOutput.get("journey");

                    if ("/journey/check-existing-identity".equals(journey)) {
                        lambdaOutput =
                                checkExistingIdentityHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/reset-identity".equals(journey)) {
                        lambdaOutput =
                                resetIdentityHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if (journey != null
                            && journey.matches("/journey/cri/build-oauth-request/.*")) {
                        lambdaOutput =
                                buildCriOauthRequestHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/build-client-oauth-response".equals(journey)) {
                        lambdaOutput =
                                buildClientOauthResponseHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/ci-scoring".equals(journey)) {
                        lambdaOutput =
                                ciScoringHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/check-gpg45-score".equals(journey)) {
                        ProcessRequest processRequest = buildProcessRequest(request, lambdaOutput);
                        lambdaOutput =
                                checkGpg45ScoreHandler.handleRequest(processRequest, EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else {
                        return gson.toJson(processJourneyEventOutput);
                    }
                }
            };

    public Route buildProvenUserIdentityDetails =
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

    public Route criCallBack =
            (Request request, Response response) -> {
                Map<String, Object> validateLambdaOutput =
                        validateOAuthCallbackHandler.handleRequest(
                                buildCriCallbackRequest(request), EMPTY_CONTEXT);

                if (!validateLambdaOutput.containsKey("journey")
                        || !"/journey/cri/access-token"
                                .equals(validateLambdaOutput.get("journey"))) {
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

                if (!retrieveCredLambdaOutput.containsKey("journey")
                        || !"/journey/ci-scoring".equals(retrieveCredLambdaOutput.get("journey"))) {
                    return gson.toJson(retrieveCredLambdaOutput);
                }

                Map<String, Object> ciScoringLambdaOutput =
                        ciScoringHandler.handleRequest(
                                buildJourneyRequest(request, null), EMPTY_CONTEXT);

                if (!ciScoringLambdaOutput.containsKey("journey")
                        || !"/journey/next".equals(ciScoringLambdaOutput.get("journey"))) {
                    return gson.toJson(ciScoringLambdaOutput);
                }

                Map<String, Object> evaluateGpg45LambdaOutput =
                        evaluateGpg45ScoresHandler.handleRequest(
                                buildJourneyRequest(request, null), EMPTY_CONTEXT);

                return gson.toJson(evaluateGpg45LambdaOutput);
            };

    public Route token =
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

    public Route userIdentity =
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

    private static JourneyRequest buildJourneyRequest(Request request, String journey) {
        return JourneyRequest.builder()
                .ipvSessionId(request.headers("ipv-session-id"))
                .ipAddress(request.headers("ip-address"))
                .clientOAuthSessionId(request.headers("client-session-id"))
                .featureSet(request.headers("feature-set"))
                .journey(journey)
                .build();
    }

    private Map<String, String> buildCriReturnLambdaInput(Request request) {
        HashMap<String, String> nextLambdaInput = new HashMap<>();
        nextLambdaInput.put("ipvSessionId", request.headers("ipv-session-id"));
        nextLambdaInput.put("ipAddress", request.headers("ip-address"));
        nextLambdaInput.put("featureSet", request.headers("feature-set"));
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
                .ipvSessionId(request.headers("ipv-session-id"))
                .redirectUri(requestBody.get("redirectUri"))
                .state(requestBody.get("state"))
                .error(requestBody.get("error"))
                .errorDescription(requestBody.get("errorDescription"))
                .ipAddress(request.headers("ip-address"))
                .featureSet(request.headers("feature-set"))
                .build();
    }

    private ProcessRequest buildProcessRequest(
            Request request, Map<String, Object> previousLambdaOutput) {
        return ProcessRequest.processRequestBuilder()
                .ipvSessionId(request.headers("ipv-session-id"))
                .ipAddress(request.headers("ip-address"))
                .clientOAuthSessionId(request.headers("client-session-id"))
                .featureSet(request.headers("feature-set"))
                .journey((String) previousLambdaOutput.get("journey"))
                .scoreType((String) previousLambdaOutput.get("scoreType"))
                .scoreThreshold((int) previousLambdaOutput.get("scoreThreshold"))
                .build();
    }
}
