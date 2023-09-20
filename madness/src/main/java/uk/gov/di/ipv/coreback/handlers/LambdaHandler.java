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

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class LambdaHandler {

    private static final Gson gson = new Gson();
    public static final CoreContext EMPTY_CONTEXT = new CoreContext();
    private static final Logger LOGGER = LoggerFactory.getLogger(LambdaHandler.class);
    public static final Type MAP_STRING_STRING_TYPE =
            new TypeToken<Map<String, String>>() {}.getType();

    public static final String APPLICATION_JSON = "application/json";
    public static Route initialiseSession =
            (Request request, Response response) -> {
                logRequest(request);
                InitialiseIpvSessionHandler initialiseIpvSessionHandler =
                        new InitialiseIpvSessionHandler();

                APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                        new APIGatewayProxyRequestEvent();
                apiGatewayProxyRequestEvent.setBody(request.body());
                apiGatewayProxyRequestEvent.setHeaders(getHeadersMap(request));

                APIGatewayProxyResponseEvent responseEvent =
                        initialiseIpvSessionHandler.handleRequest(
                                apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

                response.status(responseEvent.getStatusCode());
                response.type(APPLICATION_JSON);
                return responseEvent.getBody();
            };

    public static Route journeyEngine =
            (Request request, Response response) -> {
                logRequest(request);
                String journey = request.pathInfo();

                ProcessJourneyEventHandler processJourneyEventHandler =
                        new ProcessJourneyEventHandler();
                Map<String, Object> lambdaOutput = new HashMap<>();
                Map<String, Object> processJourneyEventOutput;
                while (true) {
                    Map<String, String> processJourneyEventLambdaInput =
                            gson.fromJson(
                                    gson.toJson(buildJourneyRequest(request, journey)),
                                    MAP_STRING_STRING_TYPE);

                    processJourneyEventOutput =
                            processJourneyEventHandler.handleRequest(
                                    processJourneyEventLambdaInput, EMPTY_CONTEXT);

                    journey = (String) processJourneyEventOutput.get("journey");

                    if ("/journey/check-existing-identity".equals(journey)) {
                        CheckExistingIdentityHandler checkExistingIdentityHandler =
                                new CheckExistingIdentityHandler();
                        lambdaOutput =
                                checkExistingIdentityHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            response.status(200);
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/reset-identity".equals(journey)) {
                        ResetIdentityHandler resetIdentityHandler = new ResetIdentityHandler();
                        lambdaOutput =
                                resetIdentityHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            response.status(200);
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if (journey != null
                            && journey.matches("/journey/cri/build-oauth-request/.*")) {
                        BuildCriOauthRequestHandler buildCriOauthRequestHandler =
                                new BuildCriOauthRequestHandler();
                        lambdaOutput =
                                buildCriOauthRequestHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            response.status(200);
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/build-client-oauth-response".equals(journey)) {
                        BuildClientOauthResponseHandler buildClientOauthResponseHandler =
                                new BuildClientOauthResponseHandler();
                        lambdaOutput =
                                buildClientOauthResponseHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            response.status(200);
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/ci-scoring".equals(journey)) {
                        CiScoringHandler ciScoringHandler = new CiScoringHandler();
                        lambdaOutput =
                                ciScoringHandler.handleRequest(
                                        buildJourneyRequest(request, journey), EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            response.status(200);
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else if ("/journey/check-gpg45-score".equals(journey)) {
                        CheckGpg45ScoreHandler checkGpg45ScoreHandler =
                                new CheckGpg45ScoreHandler();
                        ProcessRequest processRequest =
                                (ProcessRequest) buildJourneyRequest(request, journey);
                        processRequest.setScoreThreshold((int) lambdaOutput.get("scoreThreshold"));
                        processRequest.setScoreType((String) lambdaOutput.get("scoreType"));

                        lambdaOutput =
                                checkGpg45ScoreHandler.handleRequest(processRequest, EMPTY_CONTEXT);
                        if (!lambdaOutput.containsKey("journey")) {
                            response.status(200);
                            return gson.toJson(lambdaOutput);
                        }
                        journey = (String) lambdaOutput.get("journey");
                    } else {
                        response.status(200);
                        return gson.toJson(processJourneyEventOutput);
                    }
                }
            };

    public static Route buildClientOauthResponse =
            (Request request, Response response) -> {
                logRequest(request);
                BuildClientOauthResponseHandler buildClientOauthResponseHandler =
                        new BuildClientOauthResponseHandler();
                Map<String, Object> lambdaOutput =
                        buildClientOauthResponseHandler.handleRequest(
                                buildJourneyRequest(
                                        gson.fromJson(request.body(), MAP_STRING_STRING_TYPE),
                                        null),
                                EMPTY_CONTEXT);

                response.body(gson.toJson(lambdaOutput));
                response.status(200);
                return response;
            };

    public static Route buildProvenUserIdentityDetails =
            (Request request, Response response) -> {
                logRequest(request);
                BuildProvenUserIdentityDetailsHandler buildProvenUserIdentityDetailsHandler =
                        new BuildProvenUserIdentityDetailsHandler();
                Map<String, Object> lambdaOutput =
                        buildProvenUserIdentityDetailsHandler.handleRequest(
                                buildJourneyRequest(
                                        gson.fromJson(request.body(), MAP_STRING_STRING_TYPE),
                                        null),
                                EMPTY_CONTEXT);

                response.body(gson.toJson(lambdaOutput));
                response.status(200);
                return response;
            };

    public static Route criCallBack =
            (Request request, Response response) -> {
                logRequest(request);
                Map<String, String> requestBody =
                        gson.fromJson(request.body(), MAP_STRING_STRING_TYPE);
                ValidateOAuthCallbackHandler validateOAuthCallbackHandler =
                        new ValidateOAuthCallbackHandler();
                CriCallbackRequest callBackRequest =
                        CriCallbackRequest.builder()
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
                Map<String, Object> validateLambdaOutput =
                        validateOAuthCallbackHandler.handleRequest(callBackRequest, EMPTY_CONTEXT);

                if (!validateLambdaOutput.containsKey("journey")) {
                    response.status(200);
                    return gson.toJson(validateLambdaOutput);
                }

                RetrieveCriOauthAccessTokenHandler retrieveCriOauthAccessTokenHandler =
                        new RetrieveCriOauthAccessTokenHandler();
                try {
                    retrieveCriOauthAccessTokenHandler.handleRequest(
                            buildCriReturnLambdaInput(request), EMPTY_CONTEXT);
                } catch (JourneyError | IllegalArgumentException e) {
                    response.status(200);
                    return "{\"journey\":\"/journey/error\"}";
                }

                RetrieveCriCredentialHandler retrieveCriCredentialHandler =
                        new RetrieveCriCredentialHandler();
                Map<String, Object> retrieveCredLambdaOutput =
                        retrieveCriCredentialHandler.handleRequest(
                                buildCriReturnLambdaInput(request), EMPTY_CONTEXT);

                if (!retrieveCredLambdaOutput.containsKey("journey")) {
                    response.status(200);
                    return gson.toJson(retrieveCredLambdaOutput);
                }

                CiScoringHandler ciScoringHandler = new CiScoringHandler();
                Map<String, Object> ciScoringLambdaOutput =
                        ciScoringHandler.handleRequest(
                                buildJourneyRequest(request, null), EMPTY_CONTEXT);

                if (!ciScoringLambdaOutput.containsKey("journey")) {
                    response.status(200);
                    return gson.toJson(ciScoringLambdaOutput);
                }

                EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler =
                        new EvaluateGpg45ScoresHandler();
                Map<String, Object> evaluateGpg45LambdaOutput =
                        evaluateGpg45ScoresHandler.handleRequest(
                                buildJourneyRequest(request, null), EMPTY_CONTEXT);

                response.status(200);
                return gson.toJson(evaluateGpg45LambdaOutput);
            };

    public static Route token =
            (Request request, Response response) -> {
                logRequest(request);
                IssueClientAccessTokenHandler issueClientAccessTokenHandler =
                        new IssueClientAccessTokenHandler();

                APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                        new APIGatewayProxyRequestEvent();
                apiGatewayProxyRequestEvent.setBody(request.body());
                apiGatewayProxyRequestEvent.setHeaders(
                        request.headers().stream()
                                .collect(
                                        Collectors.toMap(
                                                Function.identity(), Function.identity())));

                APIGatewayProxyResponseEvent responseEvent =
                        issueClientAccessTokenHandler.handleRequest(
                                apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

                response.status(responseEvent.getStatusCode());
                response.type(APPLICATION_JSON);
                return responseEvent.getBody();
            };

    public static Route userIdentity =
            (Request request, Response response) -> {
                logRequest(request);
                BuildUserIdentityHandler buildUserIdentityHandler = new BuildUserIdentityHandler();

                APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                        new APIGatewayProxyRequestEvent();
                apiGatewayProxyRequestEvent.setBody(request.body());
                apiGatewayProxyRequestEvent.setHeaders(getHeadersMap(request));

                APIGatewayProxyResponseEvent responseEvent =
                        buildUserIdentityHandler.handleRequest(
                                apiGatewayProxyRequestEvent, EMPTY_CONTEXT);

                response.status(responseEvent.getStatusCode());
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

    private static Map<String, String> buildCriReturnLambdaInput(Request request) {
        HashMap<String, String> nextLambdaInput = new HashMap<>();
        nextLambdaInput.put("ipvSessionId", request.headers("ipv-session-id"));
        nextLambdaInput.put("ipAddress", request.headers("ip-address"));
        nextLambdaInput.put("featureSet", request.headers("feature-set"));
        return nextLambdaInput;
    }

    private static Map<String, String> stringObjectToStringString(Map<String, Object> input) {
        return input.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> (String) e.getValue()));
    }

    private static void logRequest(Request request) {
        LOGGER.info("### Request ###");
        LOGGER.info("Path: {}", request.pathInfo());
        LOGGER.info("Headers: {}", getHeadersMap(request));
        LOGGER.info("Body: {}", request.body());
    }

    private static void logResponse(Response response) {
        LOGGER.info("### Response ###");
        LOGGER.info("Status: {}", response.status());
    }

    private static Map<String, String> getHeadersMap(Request request) {
        Map<String, String> headers = new HashMap<>();
        request.headers().forEach(header -> headers.put(header, request.headers(header)));

        return headers;
    }
}
