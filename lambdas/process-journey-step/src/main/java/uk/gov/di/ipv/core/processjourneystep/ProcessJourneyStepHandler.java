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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneystep.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachine;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineInitializer;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.StateMachineNotFoundException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.PageResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_STEP;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_TYPE;
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
    private final Map<IpvJourneyTypes, StateMachine> stateMachines;

    public ProcessJourneyStepHandler(
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            List<IpvJourneyTypes> journeyTypes)
            throws IOException {
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.stateMachines = loadStateMachines(journeyTypes);
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessJourneyStepHandler() throws IOException {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.stateMachines = loadStateMachines(List.of(IPV_CORE_MAIN_JOURNEY));
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            String journeyStep = StepFunctionHelpers.getJourneyStep(input);
            String featureSet = StepFunctionHelpers.getFeatureSet(input);
            configService.setFeatureSet(featureSet);

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            if (ipvSessionItem == null) {
                LOGGER.warn("Failed to find ipv-session");
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_ID);
            }

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
        }
    }

    @Tracing
    private Map<String, Object> executeJourneyEvent(
            String journeyStep, IpvSessionItem ipvSessionItem) throws JourneyEngineException {
        String currentUserState = ipvSessionItem.getUserState();
        if (sessionIsNewlyExpired(ipvSessionItem)) {
            updateUserSessionForTimeout(currentUserState, ipvSessionItem);
            return new PageResponse(PYIC_TIMEOUT_UNRECOVERABLE_ID).value();
        }

        try {
            StateMachine stateMachine = stateMachines.get(ipvSessionItem.getJourneyType());
            if (stateMachine == null) {
                throw new StateMachineNotFoundException(
                        String.format(
                                "State machine not found for journey type: '%s'",
                                ipvSessionItem.getJourneyType()));
            }
            LOGGER.info(
                    "Found state machine for journey type: {}",
                    ipvSessionItem.getJourneyType().getValue());

            State newState =
                    stateMachine.transition(
                            ipvSessionItem.getUserState(),
                            journeyStep,
                            JourneyContext.withFeatureSet(configService.getFeatureSet()));

            updateUserState(
                    ipvSessionItem.getUserState(), newState.getName(), journeyStep, ipvSessionItem);

            clearOauthSessionIfExists(ipvSessionItem);

            ipvSessionService.updateIpvSession(ipvSessionItem);

            return newState.getResponse().value();
        } catch (UnknownStateException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), e.getMessage())
                            .with(LOG_USER_STATE.getFieldName(), ipvSessionItem.getUserState()));
            throw new JourneyEngineException(
                    "Invalid journey state encountered, failed to execute journey engine step.");
        } catch (UnknownEventException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), e.getMessage())
                            .with(LOG_JOURNEY_STEP.getFieldName(), journeyStep));
            throw new JourneyEngineException(
                    "Invalid journey event provided, failed to execute journey engine step.");
        } catch (StateMachineNotFoundException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), e.getMessage())
                            .with(LOG_JOURNEY_STEP.getFieldName(), journeyStep)
                            .with(
                                    LOG_JOURNEY_TYPE.getFieldName(),
                                    ipvSessionItem.getJourneyType()));
            throw new JourneyEngineException(
                    "State machine not found for journey type, failed to execute journey engine step");
        }
    }

    @Tracing
    private void updateUserState(
            String oldState, String newState, String journeyStep, IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setUserState(newState);
        var message =
                new StringMapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", journeyStep)
                        .with("from", oldState)
                        .with("to", newState);
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

    @Tracing
    private Map<IpvJourneyTypes, StateMachine> loadStateMachines(List<IpvJourneyTypes> journeyTypes)
            throws IOException {
        EnumMap<IpvJourneyTypes, StateMachine> stateMachinesMap =
                new EnumMap<>(IpvJourneyTypes.class);
        for (IpvJourneyTypes journeyType : journeyTypes) {
            stateMachinesMap.put(
                    journeyType, new StateMachine(new StateMachineInitializer(journeyType)));
        }
        return stateMachinesMap;
    }
}
