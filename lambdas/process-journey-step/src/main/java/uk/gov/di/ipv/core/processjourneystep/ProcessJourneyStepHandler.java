package uk.gov.di.ipv.core.processjourneystep;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
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

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;

public class ProcessJourneyStepHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String PYIC_TECHNICAL_ERROR_PAGE_ID = "pyi-technical";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";

    private final IpvSessionService ipvSessionService;
    private final ConfigurationService configurationService;

    private StateMachine stateMachine;

    public ProcessJourneyStepHandler(
            IpvSessionService ipvSessionService, ConfigurationService configurationService) {
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessJourneyStepHandler() throws IOException {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            String journeyStep = StepFunctionHelpers.getJourneyStep(input);

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            if (ipvSessionItem == null) {
                LOGGER.warn("Failed to find ipv-session");
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_ID);
            }

            this.stateMachine =
                    new StateMachine(
                            new StateMachineInitializer(
                                    configurationService.getEnvironmentVariable(
                                            EnvironmentVariable.ENVIRONMENT),
                                    ipvSessionItem.getJourneyType()));

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    ipvSessionItem.getClientSessionDetails().getGovukSigninJourneyId());

            return executeJourneyEvent(journeyStep, ipvSessionItem);

        } catch (HttpResponseExceptionWithErrorBody e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    e.getResponseCode(), e.getErrorResponse());
        } catch (JourneyEngineException e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_JOURNEY_ENGINE_STEP);
        } catch (IOException e) {
            LOGGER.error("Failed to initialise state machine", e);
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_INITIALISE_STATE_MACHINE);
        }
    }

    @Tracing
    private Map<String, Object> executeJourneyEvent(
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
            LOGGER.error("Unknown journey state: {}", ipvSessionItem.getUserState());
            throw new JourneyEngineException(
                    "Invalid journey state encountered, failed to execute journey engine step.");
        } catch (UnknownEventException e) {
            LOGGER.error("Unknown journey event: {}", journeyStep);
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
                new StringMapMessage()
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
                new StringMapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", "timeout")
                        .with("from", oldState)
                        .with("to", CORE_SESSION_TIMEOUT_STATE);
        LOGGER.info(message);
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
