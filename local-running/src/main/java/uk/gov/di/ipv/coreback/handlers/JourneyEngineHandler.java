package uk.gov.di.ipv.coreback.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import spark.Request;
import spark.Response;
import spark.Route;
import uk.gov.di.ipv.core.buildclientoauthresponse.BuildClientOauthResponseHandler;
import uk.gov.di.ipv.core.buildcrioauthrequest.BuildCriOauthRequestHandler;
import uk.gov.di.ipv.core.callticfcri.CallTicfCriHandler;
import uk.gov.di.ipv.core.checkexistingidentity.CheckExistingIdentityHandler;
import uk.gov.di.ipv.core.checkgpg45score.CheckGpg45ScoreHandler;
import uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.processjourneyevent.ProcessJourneyEventHandler;
import uk.gov.di.ipv.coreback.domain.CoreContext;
import uk.gov.di.ipv.coreback.exceptions.UnrecognisedJourneyException;

import java.io.IOException;
import java.util.Map;

public class JourneyEngineHandler {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final CoreContext EMPTY_CONTEXT = new CoreContext();
    public static final String APPLICATION_JSON = "application/json";

    public static final String JOURNEY = "journey";
    public static final String IPV_SESSION_ID = "ipv-session-id";
    public static final String IP_ADDRESS = "ip-address";
    public static final String CLIENT_SESSION_ID = "client-session-id";
    public static final String FEATURE_SET = "feature-set";

    private final ProcessJourneyEventHandler processJourneyEventHandler;
    private final CheckExistingIdentityHandler checkExistingIdentityHandler;
    private final BuildCriOauthRequestHandler buildCriOauthRequestHandler;
    private final BuildClientOauthResponseHandler buildClientOauthResponseHandler;
    private final CheckGpg45ScoreHandler checkGpg45ScoreHandler;
    private final EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;
    private final CallTicfCriHandler callTicfCriHandler;

    public JourneyEngineHandler() throws IOException {
        this.processJourneyEventHandler = new ProcessJourneyEventHandler();
        this.checkExistingIdentityHandler = new CheckExistingIdentityHandler();
        this.buildCriOauthRequestHandler = new BuildCriOauthRequestHandler();
        this.buildClientOauthResponseHandler = new BuildClientOauthResponseHandler();
        this.checkGpg45ScoreHandler = new CheckGpg45ScoreHandler();
        this.evaluateGpg45ScoresHandler = new EvaluateGpg45ScoresHandler();
        this.callTicfCriHandler = new CallTicfCriHandler();
    }

    private final Route journeyEngine =
            (Request request, Response response) -> {
                response.type(APPLICATION_JSON);
                String journeyEvent = request.pathInfo();

                while (true) {
                    var processJourneyEventOutput = processJourneyEvent(request, journeyEvent);

                    if (!processJourneyEventOutput.containsKey(JOURNEY)) {
                        return OBJECT_MAPPER.writeValueAsString(processJourneyEventOutput);
                    }

                    var processJourneyStepOutput =
                            processJourneyStep(request, processJourneyEventOutput);

                    if (!processJourneyStepOutput.containsKey(JOURNEY)) {
                        return OBJECT_MAPPER.writeValueAsString(processJourneyStepOutput);
                    }

                    journeyEvent = (String) processJourneyStepOutput.get(JOURNEY);
                }
            };

    public Route getJourneyEngine() {
        return journeyEngine;
    }

    // Corresponds to the ProcessJourneyStep state in the step function
    private Map<String, Object> processJourneyEvent(Request request, String journeyEvent) {
        return processJourneyEventHandler.handleRequest(
                buildJourneyRequest(request, journeyEvent), EMPTY_CONTEXT);
    }

    // Corresponds to the ProcessJourneyStepResult state in the step function
    private Map<String, Object> processJourneyStep(
            Request request, Map<String, Object> processJourneyEventOutput) {
        var journeyStep = (String) processJourneyEventOutput.get(JOURNEY);

        return switch (journeyStep) {
            case "/journey/check-existing-identity" -> checkExistingIdentityHandler.handleRequest(
                    buildJourneyRequest(request, journeyStep), EMPTY_CONTEXT);
            case "/journey/build-client-oauth-response" -> buildClientOauthResponseHandler
                    .handleRequest(buildJourneyRequest(request, journeyStep), EMPTY_CONTEXT);
            case "/journey/evaluate-gpg45-scores" -> evaluateGpg45ScoresHandler.handleRequest(
                    buildProcessRequest(request, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/check-gpg45-scores" -> checkGpg45ScoreHandler.handleRequest(
                    buildProcessRequest(request, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/call-ticf-cri" -> callTicfCriHandler.handleRequest(
                    buildProcessRequest(request, processJourneyEventOutput), EMPTY_CONTEXT);
            default -> {
                if (journeyStep.matches("/journey/cri/build-oauth-request/.*")) {
                    yield buildCriOauthRequestHandler.handleRequest(
                            buildJourneyRequest(request, journeyStep), EMPTY_CONTEXT);
                } else {
                    throw new UnrecognisedJourneyException(
                            String.format("Journey not configured: %s", journeyStep));
                }
            }
        };
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
}
