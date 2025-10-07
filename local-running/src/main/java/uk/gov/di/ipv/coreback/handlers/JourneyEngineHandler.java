package uk.gov.di.ipv.coreback.handlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import io.javalin.http.Context;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.buildclientoauthresponse.BuildClientOauthResponseHandler;
import uk.gov.di.ipv.core.buildcrioauthrequest.BuildCriOauthRequestHandler;
import uk.gov.di.ipv.core.calldcmawasynccri.CallDcmawAsyncCriHandler;
import uk.gov.di.ipv.core.checkexistingidentity.CheckExistingIdentityHandler;
import uk.gov.di.ipv.core.checkgpg45score.CheckGpg45ScoreHandler;
import uk.gov.di.ipv.core.checkreverificationidentity.CheckReverificationIdentityHandler;
import uk.gov.di.ipv.core.library.domain.CriJourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.service.LocalConfigService;
import uk.gov.di.ipv.core.processcandidateidentity.ProcessCandidateIdentityHandler;
import uk.gov.di.ipv.core.processjourneyevent.ProcessJourneyEventHandler;
import uk.gov.di.ipv.core.resetsessionidentity.ResetSessionIdentityHandler;
import uk.gov.di.ipv.coreback.domain.CoreContext;
import uk.gov.di.ipv.coreback.exceptions.UnrecognisedJourneyException;

import java.io.IOException;
import java.util.Map;

import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_CALL_DCMAW_ASYNC_CRI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_CHECK_EXISTING_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_CHECK_GPG45_SCORE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_CHECK_REVERIFICATION_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PROCESS_CANDIDATE_IDENTITY;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_RESET_SESSION_IDENTITY_PATH;

public class JourneyEngineHandler {
    public static final CoreContext EMPTY_CONTEXT = new CoreContext();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final String JOURNEY = "journey";
    public static final String IPV_SESSION_ID = "ipv-session-id";
    public static final String IP_ADDRESS = "ip-address";
    public static final String ENCODED_DEVICE_INFORMATION = "txma-audit-encoded";
    public static final String CLIENT_SESSION_ID = "client-session-id";
    public static final String FEATURE_SET = "feature-set";
    public static final String LANGUAGE = "language";

    private final LocalConfigService configService;
    private final ProcessJourneyEventHandler processJourneyEventHandler;
    private final CheckExistingIdentityHandler checkExistingIdentityHandler;
    private final ResetSessionIdentityHandler resetSessionIdentityHandler;
    private final BuildCriOauthRequestHandler buildCriOauthRequestHandler;
    private final BuildClientOauthResponseHandler buildClientOauthResponseHandler;
    private final CheckGpg45ScoreHandler checkGpg45ScoreHandler;
    private final CallDcmawAsyncCriHandler callDcmawAsyncHandler;
    private final CheckReverificationIdentityHandler checkReverificationIdentityHandler;
    private final ProcessCandidateIdentityHandler processCandidateIdentityHandler;

    public JourneyEngineHandler() throws IOException {
        this.configService = new LocalConfigService();
        this.processJourneyEventHandler = new ProcessJourneyEventHandler(configService);
        this.checkExistingIdentityHandler = new CheckExistingIdentityHandler(configService);
        this.resetSessionIdentityHandler = new ResetSessionIdentityHandler(configService);
        this.buildCriOauthRequestHandler = new BuildCriOauthRequestHandler(configService);
        this.buildClientOauthResponseHandler = new BuildClientOauthResponseHandler(configService);
        this.checkGpg45ScoreHandler = new CheckGpg45ScoreHandler(configService);
        this.callDcmawAsyncHandler = new CallDcmawAsyncCriHandler(configService);
        this.checkReverificationIdentityHandler =
                new CheckReverificationIdentityHandler(configService);
        this.processCandidateIdentityHandler = new ProcessCandidateIdentityHandler(configService);
    }

    public void journeyEngine(Context ctx) throws JsonProcessingException {
        String journeyEvent = ctx.pathParam("event");
        String currentPage = ctx.queryParam("currentPage");

        while (true) {
            var processJourneyEventOutput = processJourneyEvent(ctx, currentPage, journeyEvent);

            // After the first event currentPage is no longer valid
            currentPage = "";

            if (!processJourneyEventOutput.containsKey(JOURNEY)) {
                ctx.json(processJourneyEventOutput);
                configService.removeFeatureSet();
                return;
            }

            var processJourneyStepOutput = processJourneyStep(ctx, processJourneyEventOutput);

            if (!processJourneyStepOutput.containsKey(JOURNEY)) {
                ctx.json(processJourneyStepOutput);
                configService.removeFeatureSet();
                return;
            }

            journeyEvent = (String) processJourneyStepOutput.get(JOURNEY);
        }
    }

    // Corresponds to the ProcessJourneyStep state in the step function
    private Map<String, Object> processJourneyEvent(
            Context ctx, String currentPage, String journeyEvent) throws JsonProcessingException {
        LOGGER.info(
                "LOCAL RUNNING - Processing journey event: {}, path: {}, params: {}",
                journeyEvent,
                ctx.path(),
                OBJECT_MAPPER.writeValueAsString(ctx.queryParamMap()));
        return processJourneyEventHandler.handleRequest(
                buildJourneyRequest(ctx, currentPage, journeyEvent), EMPTY_CONTEXT);
    }

    // Corresponds to the ProcessJourneyStepResult state in the step function
    private Map<String, Object> processJourneyStep(
            Context ctx, Map<String, Object> processJourneyEventOutput)
            throws JsonProcessingException {
        var journeyStep = (String) processJourneyEventOutput.get(JOURNEY);

        LOGGER.info(
                "LOCAL RUNNING - Processing journey step: {}, path: {}, params: {}",
                journeyStep,
                ctx.path(),
                OBJECT_MAPPER.writeValueAsString(ctx.queryParamMap()));
        return switch (journeyStep) {
            case JOURNEY_CHECK_EXISTING_IDENTITY_PATH ->
                    checkExistingIdentityHandler.handleRequest(
                            buildJourneyRequest(ctx, "", journeyStep), EMPTY_CONTEXT);
            case JOURNEY_RESET_SESSION_IDENTITY_PATH ->
                    resetSessionIdentityHandler.handleRequest(
                            buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH ->
                    buildClientOauthResponseHandler.handleRequest(
                            buildJourneyRequest(ctx, "", journeyStep), EMPTY_CONTEXT);
            case JOURNEY_CHECK_GPG45_SCORE_PATH ->
                    checkGpg45ScoreHandler.handleRequest(
                            buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case JOURNEY_CALL_DCMAW_ASYNC_CRI_PATH ->
                    callDcmawAsyncHandler.handleRequest(
                            buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case JOURNEY_CHECK_REVERIFICATION_IDENTITY_PATH ->
                    checkReverificationIdentityHandler.handleRequest(
                            buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            case JOURNEY_PROCESS_CANDIDATE_IDENTITY ->
                    processCandidateIdentityHandler.handleRequest(
                            buildProcessRequest(ctx, processJourneyEventOutput), EMPTY_CONTEXT);
            default -> {
                if (journeyStep.matches("/journey/cri/build-oauth-request/.*")) {
                    yield buildCriOauthRequestHandler.handleRequest(
                            buildCriJourneyRequest(ctx, journeyStep), EMPTY_CONTEXT);
                } else {
                    throw new UnrecognisedJourneyException(
                            String.format("Journey not configured: %s", journeyStep));
                }
            }
        };
    }

    private JourneyRequest buildJourneyRequest(
            Context ctx, String currentPage, String journeyEvent) {
        var currentPageParam =
                StringUtils.isBlank(currentPage)
                        ? ""
                        : String.format("?currentPage=%s", currentPage);

        var journeyWithQuery = journeyEvent + currentPageParam;

        return JourneyRequest.builder()
                .ipvSessionId(ctx.header(IPV_SESSION_ID))
                .ipAddress(ctx.header(IP_ADDRESS))
                .deviceInformation(ctx.header(ENCODED_DEVICE_INFORMATION))
                .clientOAuthSessionId(ctx.header(CLIENT_SESSION_ID))
                .featureSet(ctx.header(FEATURE_SET))
                .journey(journeyWithQuery)
                .build();
    }

    private CriJourneyRequest buildCriJourneyRequest(Context ctx, String journey) {
        return CriJourneyRequest.builder()
                .ipvSessionId(ctx.header(IPV_SESSION_ID))
                .ipAddress(ctx.header(IP_ADDRESS))
                .deviceInformation(ctx.header(ENCODED_DEVICE_INFORMATION))
                .clientOAuthSessionId(ctx.header(CLIENT_SESSION_ID))
                .featureSet(ctx.header(FEATURE_SET))
                .language(ctx.header(LANGUAGE))
                .journey(journey)
                .build();
    }

    @SuppressWarnings("unchecked")
    private ProcessRequest buildProcessRequest(
            Context ctx, Map<String, Object> processJourneyEventOutput) {
        return ProcessRequest.processRequestBuilder()
                .ipvSessionId(ctx.header(IPV_SESSION_ID))
                .ipAddress(ctx.header(IP_ADDRESS))
                .deviceInformation(ctx.header(ENCODED_DEVICE_INFORMATION))
                .clientOAuthSessionId(ctx.header(CLIENT_SESSION_ID))
                .featureSet(ctx.header(FEATURE_SET))
                .journey((String) processJourneyEventOutput.get(JOURNEY))
                .lambdaInput((Map<String, Object>) processJourneyEventOutput.get("lambdaInput"))
                .build();
    }
}
