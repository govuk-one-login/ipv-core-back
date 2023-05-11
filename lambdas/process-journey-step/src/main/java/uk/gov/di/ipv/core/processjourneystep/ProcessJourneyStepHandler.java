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
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
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
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_STEP;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_USER_STATE;

public class ProcessJourneyStepHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String PYIC_TIMEOUT_UNRECOVERABLE_ID = "pyi-timeout-unrecoverable";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";

    private final IpvSessionService ipvSessionService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private StateMachine stateMachine;

    public ProcessJourneyStepHandler(
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionService) {
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.clientOAuthSessionService = clientOAuthSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessJourneyStepHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            String journeyStep = StepFunctionHelpers.getJourneyStep(input);
            String featureSet = RequestHelper.getFeatureSet(input);
            configService.setFeatureSet(featureSet);

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            if (ipvSessionItem == null) {
                LOGGER.warn("Failed to find ipv-session");
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_ID);
            }

            this.stateMachine =
                    new StateMachine(
                            new StateMachineInitializer(
                                    configService.getEnvironmentVariable(
                                            EnvironmentVariable.ENVIRONMENT),
                                    ipvSessionItem.getJourneyType()));

            ClientOAuthSessionItem clientOAuthSessionItem;
            if (ipvSessionItem.getClientOAuthSessionId() != null) {
                clientOAuthSessionItem =
                        clientOAuthSessionService.getClientOAuthSession(
                                ipvSessionItem.getClientOAuthSessionId());
                LogHelper.attachGovukSigninJourneyIdToLogs(
                        clientOAuthSessionItem.getGovukSigninJourneyId());
            }

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
            return new PageResponse(PYIC_TIMEOUT_UNRECOVERABLE_ID).value(configService);
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

            clearOauthSessionIfExists(ipvSessionItem);

            ipvSessionService.updateIpvSession(ipvSessionItem);

            return stateMachineResult.getJourneyStepResponse().value(configService);
        } catch (UnknownStateException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Unknown journey state.")
                            .with(LOG_USER_STATE.getFieldName(), ipvSessionItem.getUserState()));
            throw new JourneyEngineException(
                    "Invalid journey state encountered, failed to execute journey engine step.");
        } catch (UnknownEventException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Unknown journey event.")
                            .with(LOG_JOURNEY_STEP.getFieldName(), journeyStep));
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
        var message =
                new StringMapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", journeyStep)
                        .with("from", oldState)
                        .with("to", updatedStateValue);
        LOGGER.info(message);
    }

    @Tracing
    private void clearOauthSessionIfExists(IpvSessionItem ipvSessionItem) {
        if (ipvSessionItem.getCriOAuthSessionId() != null) {
            ipvSessionItem.setCriOAuthSessionId(null);
        }
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
                                                        configService.getSsmParameter(
                                                                BACKEND_SESSION_TIMEOUT))));
    }
}
