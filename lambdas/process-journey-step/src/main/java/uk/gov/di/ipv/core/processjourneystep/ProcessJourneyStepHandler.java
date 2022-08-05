package uk.gov.di.ipv.core.processjourneystep;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneystep.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachine;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineInitializer;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.PageResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;

public class ProcessJourneyStepHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String JOURNEY_STEP_PARAM = "journeyStep";
    private static final String PYIC_TECHNICAL_ERROR_PAGE_ID = "pyi-technical";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";

    private final StateMachine stateMachine;
    private final IpvSessionService ipvSessionService;
    private final ConfigurationService configurationService;

    public ProcessJourneyStepHandler(
            StateMachine stateMachine,
            IpvSessionService ipvSessionService,
            ConfigurationService configurationService) {
        this.stateMachine = stateMachine;
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessJourneyStepHandler() throws IOException {
        this.configurationService = new ConfigurationService();
        this.stateMachine =
                new StateMachine(
                        new StateMachineInitializer(
                                configurationService.getEnvironmentVariable(
                                        EnvironmentVariable.ENVIRONMENT)));
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            var ipvSessionId = RequestHelper.getIpvSessionId(input);
            Map<String, String> pathParameters = input.getPathParameters();

            var errorResponse = validate(pathParameters);
            if (errorResponse.isPresent()) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
            }

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            if (ipvSessionItem == null) {
                LOGGER.warn("Failed to find ipv-session");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_ID);
            }

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    ipvSessionItem.getClientSessionDetails().getGovukSigninJourneyId());

            String journeyStep = input.getPathParameters().get(JOURNEY_STEP_PARAM);

            Map<String, String> journeyStepResponse =
                    executeJourneyEvent(journeyStep, ipvSessionItem);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, journeyStepResponse);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (JourneyEngineException e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_JOURNEY_ENGINE_STEP);
        }
    }

    @Tracing
    private Map<String, String> executeJourneyEvent(
            String journeyStep, IpvSessionItem ipvSessionItem) throws JourneyEngineException {
        String currentUserState = ipvSessionItem.getUserState();
        if (sessionIsNewlyExpired(ipvSessionItem)) {
            updateUserSessionForTimeout(currentUserState, ipvSessionItem);
            return new PageResponse(PYIC_TECHNICAL_ERROR_PAGE_ID).value(configurationService);
        }

        try {
            StateMachineResult stateMachineResult =
                    stateMachine.transition(
                            ipvSessionItem.getUserState(),
                            journeyStep,
                            JourneyContext.emptyContext());

            updateUserState(
                    ipvSessionItem.getUserState(),
                    stateMachineResult.getState().getName(),
                    journeyStep,
                    ipvSessionItem);

            return stateMachineResult.getJourneyStepResponse().value(configurationService);
        } catch (UnknownStateException e) {
            LOGGER.warn("Unknown journey state: {}", ipvSessionItem.getUserState());
            throw new JourneyEngineException(
                    "Invalid journey state encountered, failed to execute journey engine step.");
        } catch (UnknownEventException e) {
            LOGGER.warn("Unknown journey event: {}", journeyStep);
            throw new JourneyEngineException(
                    "Invalid journey event provided, failed to execute journey engine step.");
        }
    }

    @Tracing
    private void updateUserState(
            String oldState,
            String updatedStateValue,
            String journeyStep,
            IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setUserState(updatedStateValue);
        ipvSessionService.updateIpvSession(ipvSessionItem);
        var message =
                new MapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", journeyStep)
                        .with("from", oldState)
                        .with("to", updatedStateValue);
        LOGGER.info(message);
    }

    @Tracing
    private void updateUserSessionForTimeout(String oldState, IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setErrorCode(OAuth2Error.ACCESS_DENIED.getCode());
        ipvSessionItem.setErrorDescription(OAuth2Error.ACCESS_DENIED.getDescription());
        ipvSessionItem.setUserState(CORE_SESSION_TIMEOUT_STATE);
        ipvSessionService.updateIpvSession(ipvSessionItem);
        var message =
                new MapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", "timeout")
                        .with("from", oldState)
                        .with("to", CORE_SESSION_TIMEOUT_STATE);
        LOGGER.info(message);
    }

    @Tracing
    private Optional<ErrorResponse> validate(Map<String, String> pathParameters) {
        if (pathParameters.isEmpty()
                || StringUtils.isBlank(pathParameters.get(JOURNEY_STEP_PARAM))) {
            return Optional.of(ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM);
        }
        return Optional.empty();
    }

    @Tracing
    private boolean sessionIsNewlyExpired(IpvSessionItem ipvSessionItem) {
        return (!CORE_SESSION_TIMEOUT_STATE.equals(ipvSessionItem.getUserState()))
                && Instant.parse(ipvSessionItem.getCreationDateTime())
                        .isBefore(
                                Instant.now()
                                        .minusSeconds(
                                                Long.parseLong(
                                                        configurationService.getSsmParameter(
                                                                BACKEND_SESSION_TIMEOUT))));
    }
}
