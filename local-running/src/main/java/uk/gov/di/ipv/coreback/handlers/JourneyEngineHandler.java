package uk.gov.di.ipv.coreback.handlers;

import io.javalin.http.Context;
import uk.gov.di.ipv.core.buildclientoauthresponse.BuildClientOauthResponseHandler;
import uk.gov.di.ipv.core.buildcrioauthrequest.BuildCriOauthRequestHandler;
import uk.gov.di.ipv.core.calldcmawasynccri.CallDcmawAsyncCriHandler;
import uk.gov.di.ipv.core.callticfcri.CallTicfCriHandler;
import uk.gov.di.ipv.core.checkcoi.CheckCoiHandler;
import uk.gov.di.ipv.core.checkexistingidentity.CheckExistingIdentityHandler;
import uk.gov.di.ipv.core.checkgpg45score.CheckGpg45ScoreHandler;
import uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.processjourneyevent.ProcessJourneyEventHandler;
import uk.gov.di.ipv.core.resetsessionidentity.ResetSessionIdentityHandler;
import uk.gov.di.ipv.core.storeidentity.StoreIdentityHandler;
import uk.gov.di.ipv.coreback.domain.CoreContext;
import uk.gov.di.ipv.coreback.exceptions.UnrecognisedJourneyException;

import java.io.IOException;
import java.util.Map;

public class JourneyEngineHandler {
    public static final CoreContext EMPTY_CONTEXT = new CoreContext();

    public static final String JOURNEY = "journey";
    public static final String IPV_SESSION_ID = "ipv-session-id";
    public static final String IP_ADDRESS = "ip-address";
    public static final String ENCODED_DEVICE_INFORMATION = "txma-audit-encoded";
    public static final String CLIENT_SESSION_ID = "client-session-id";
    public static final String FEATURE_SET = "feature-set";
    public static final String LANGUAGE = "language";

    private final ProcessJourneyEventHandler processJourneyEventHandler;
    private final CheckExistingIdentityHandler checkExistingIdentityHandler;
    private final ResetSessionIdentityHandler resetSessionIdentityHandler;
    private final BuildCriOauthRequestHandler buildCriOauthRequestHandler;
    private final BuildClientOauthResponseHandler buildClientOauthResponseHandler;
    private final CheckGpg45ScoreHandler checkGpg45ScoreHandler;
    private final EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;
    private final CallTicfCriHandler callTicfCriHandler;
    private final CallDcmawAsyncCriHandler callDcmawAsyncHandler;
    private final StoreIdentityHandler storeIdentityHandler;
    private final CheckCoiHandler checkCoiHandler;

    public JourneyEngineHandler() throws IOException {
        this.processJourneyEventHandler = new ProcessJourneyEventHandler();
        this.checkExistingIdentityHandler = new CheckExistingIdentityHandler();
        this.resetSessionIdentityHandler = new ResetSessionIdentityHandler();
        this.buildCriOauthRequestHandler = new BuildCriOauthRequestHandler();
        this.buildClientOauthResponseHandler = new BuildClientOauthResponseHandler();
        this.checkGpg45ScoreHandler = new CheckGpg45ScoreHandler();
        this.evaluateGpg45ScoresHandler = new EvaluateGpg45ScoresHandler();
        this.callTicfCriHandler = new CallTicfCriHandler();
        this.callDcmawAsyncHandler = new CallDcmawAsyncCriHandler();
        this.storeIdentityHandler = new StoreIdentityHandler();
        this.checkCoiHandler = new CheckCoiHandler();
    }

    public void journeyEngine(Context ctx) {
        String journeyEvent = ctx.pathParam("event");

        while (true) {
            var processJourneyEventOutput = processJourneyEvent(ctx, journeyEvent);

            if (!processJourneyEventOutput.containsKey(JOURNEY)) {
                ctx.json(processJourneyEventOutput);
                return;
            }

            var processJourneyStepOutput = processJourneyStep(ctx, processJourneyEventOutput);

            if (!processJourneyStepOutput.containsKey(JOURNEY)) {
                ctx.json(processJourneyStepOutput);
                return;
            }

            journeyEvent = (String) processJourneyStepOutput.get(JOURNEY);
        }
    }

    // Corresponds to the ProcessJourneyStep state in the step function
    private Map<String, Object> processJourneyEvent(Context ctx, String journeyEvent) {
        return processJourneyEventHandler.handleRequest(
                buildJourneyRequest(ctx, journeyEvent), EMPTY_CONTEXT);
    }

    // Corresponds to the ProcessJourneyStepResult state in the step function
    private Map<String, Object> processJourneyStep(
            Context ctx, Map<String, Object> processJourneyEventOutput) {
        var journeyStep = (String) processJourneyEventOutput.get(JOURNEY);

        return switch (journeyStep) {
            case "/journey/check-existing-identity" -> checkExistingIdentityHandler.handleRequest(
                    buildJourneyRequest(ctx, journeyStep), EMPTY_CONTEXT);
            case "/journey/reset-session-identity" -> resetSessionIdentityHandler.handleRequest(
                    buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/build-client-oauth-response" -> buildClientOauthResponseHandler
                    .handleRequest(buildJourneyRequest(ctx, journeyStep), EMPTY_CONTEXT);
            case "/journey/evaluate-gpg45-scores" -> evaluateGpg45ScoresHandler.handleRequest(
                    buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/check-gpg45-score" -> checkGpg45ScoreHandler.handleRequest(
                    buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/call-ticf-cri" -> callTicfCriHandler.handleRequest(
                    buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/call-dcmaw-async-cri" -> callDcmawAsyncHandler.handleRequest(
                    buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/store-identity" -> storeIdentityHandler.handleRequest(
                    buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case "/journey/check-coi" -> checkCoiHandler.handleRequest(
                    buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            default -> {
                if (journeyStep.matches("/journey/cri/build-oauth-request/.*")) {
                    yield buildCriOauthRequestHandler.handleRequest(
                            buildJourneyRequest(ctx, journeyStep), EMPTY_CONTEXT);
                } else {
                    throw new UnrecognisedJourneyException(
                            String.format("Journey not configured: %s", journeyStep));
                }
            }
        };
    }

    private JourneyRequest buildJourneyRequest(Context ctx, String journey) {
        return JourneyRequest.builder()
                .ipvSessionId(ctx.header(IPV_SESSION_ID))
                .ipAddress(ctx.header(IP_ADDRESS))
                .deviceInformation(ctx.header(ENCODED_DEVICE_INFORMATION))
                .clientOAuthSessionId(ctx.header(CLIENT_SESSION_ID))
                .featureSet(ctx.header(FEATURE_SET))
                .language(ctx.header(LANGUAGE))
                .journey(journey)
                .build();
    }

    private ProcessRequest buildProcessRequest(
            Context ctx, Map<String, Object> processJourneyEventOutput) {
        return ProcessRequest.processRequestBuilder()
                .ipvSessionId(ctx.header(IPV_SESSION_ID))
                .ipAddress(ctx.header(IP_ADDRESS))
                .deviceInformation(ctx.header(ENCODED_DEVICE_INFORMATION))
                .clientOAuthSessionId(ctx.header(CLIENT_SESSION_ID))
                .featureSet(ctx.header(FEATURE_SET))
                .language(ctx.header(LANGUAGE))
                .journey((String) processJourneyEventOutput.get(JOURNEY))
                .lambdaInput((Map<String, Object>) processJourneyEventOutput.get("lambdaInput"))
                .build();
    }
}
