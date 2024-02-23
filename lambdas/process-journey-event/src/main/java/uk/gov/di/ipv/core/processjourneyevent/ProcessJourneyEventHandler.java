package uk.gov.di.ipv.core.processjourneyevent;

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
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachine;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializer;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializerMode;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.StateMachineNotFoundException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.JourneyChangeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.StepResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_EVENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_TYPE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_USER_STATE;

public class ProcessJourneyEventHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";
    private static final String NEXT_EVENT = "next";
    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final Map<IpvJourneyTypes, StateMachine> stateMachines;

    public ProcessJourneyEventHandler(
            AuditService auditService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            List<IpvJourneyTypes> journeyTypes,
            StateMachineInitializerMode stateMachineInitializerMode)
            throws IOException {
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.configService = configService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.stateMachines = loadStateMachines(journeyTypes, stateMachineInitializerMode);
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessJourneyEventHandler() throws IOException {
        this.configService = new ConfigService();
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.stateMachines =
                loadStateMachines(
                        List.of(IpvJourneyTypes.values()), StateMachineInitializerMode.STANDARD);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            // Extract variables
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            String ipAddress = StepFunctionHelpers.getIpAddress(input);
            String journeyEvent = StepFunctionHelpers.getJourneyEvent(input);
            String featureSet = StepFunctionHelpers.getFeatureSet(input);

            // Get/ set session items/ config
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            if (ipvSessionItem == null) {
                LOGGER.error(LogHelper.buildLogMessage("Failed to find ipv-session"));
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_ID);
            }
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            configService.setFeatureSet(featureSet);

            // Attach variables to logs
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            StepResponse stepResponse = executeJourneyEvent(journeyEvent, ipvSessionItem);

            if (Boolean.TRUE.equals(stepResponse.getMitigationStart())) {
                sendMitigationStartAuditEvent(ipvSessionId, ipAddress, clientOAuthSessionItem);
            }

            return stepResponse.value();
        } catch (HttpResponseExceptionWithErrorBody e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    e.getResponseCode(), e.getErrorResponse());
        } catch (JourneyEngineException e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_JOURNEY_ENGINE_STEP);
        } catch (SqsException e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT);
        }
    }

    @Tracing
    private StepResponse executeJourneyEvent(String journeyEvent, IpvSessionItem ipvSessionItem)
            throws JourneyEngineException {
        if (sessionIsNewlyExpired(ipvSessionItem)) {
            updateUserSessionForTimeout(ipvSessionItem.getUserState(), ipvSessionItem);
            journeyEvent = NEXT_EVENT;
        }

        try {
            var newState = executeStateTransition(ipvSessionItem, journeyEvent);

            while (newState instanceof JourneyChangeState journeyChangeState) {
                LOGGER.info(
                        LogHelper.buildLogMessage("Transitioned to new journey type")
                                .with(
                                        LOG_JOURNEY_TYPE.getFieldName(),
                                        journeyChangeState.getJourneyType())
                                .with(
                                        LOG_USER_STATE.getFieldName(),
                                        journeyChangeState.getInitialState()));
                ipvSessionItem.setJourneyType(journeyChangeState.getJourneyType());
                ipvSessionItem.setUserState(journeyChangeState.getInitialState());
                newState = executeStateTransition(ipvSessionItem, NEXT_EVENT);
            }

            var basicState = (BasicState) newState;

            updateUserState(
                    ipvSessionItem.getUserState(),
                    basicState.getName(),
                    journeyEvent,
                    ipvSessionItem);

            clearOauthSessionIfExists(ipvSessionItem);

            ipvSessionService.updateIpvSession(ipvSessionItem);

            return basicState.getResponse();
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
                            .with(LOG_JOURNEY_EVENT.getFieldName(), journeyEvent));
            throw new JourneyEngineException(
                    "Invalid journey event provided, failed to execute journey engine step.");
        } catch (StateMachineNotFoundException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), e.getMessage())
                            .with(LOG_JOURNEY_EVENT.getFieldName(), journeyEvent)
                            .with(
                                    LOG_JOURNEY_TYPE.getFieldName(),
                                    ipvSessionItem.getJourneyType()));
            throw new JourneyEngineException(
                    "State machine not found for journey type, failed to execute journey engine step");
        }
    }

    @Tracing
    private State executeStateTransition(IpvSessionItem ipvSessionItem, String journeyEvent)
            throws StateMachineNotFoundException, UnknownEventException, UnknownStateException {
        StateMachine stateMachine = stateMachines.get(ipvSessionItem.getJourneyType());
        if (stateMachine == null) {
            throw new StateMachineNotFoundException(
                    String.format(
                            "State machine not found for journey type: '%s'",
                            ipvSessionItem.getJourneyType()));
        }
        LOGGER.debug(
                LogHelper.buildLogMessage(
                        String.format(
                                "Found state machine for journey type: %s",
                                ipvSessionItem.getJourneyType().name())));

        return stateMachine.transition(
                ipvSessionItem.getUserState(),
                journeyEvent,
                JourneyContext.withFeatureSet(configService.getFeatureSet()));
    }

    @Tracing
    private void updateUserState(
            String oldState, String newState, String journeyEvent, IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setUserState(newState);
        var message =
                new StringMapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", journeyEvent)
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
        ipvSessionItem.setJourneyType(IpvJourneyTypes.SESSION_TIMEOUT);
        updateUserState(oldState, CORE_SESSION_TIMEOUT_STATE, "timeout", ipvSessionItem);
    }

    @Tracing
    private boolean sessionIsNewlyExpired(IpvSessionItem ipvSessionItem) {
        return (!IpvJourneyTypes.SESSION_TIMEOUT.equals(ipvSessionItem.getJourneyType()))
                && Instant.parse(ipvSessionItem.getCreationDateTime())
                        .isBefore(
                                Instant.now()
                                        .minusSeconds(
                                                Long.parseLong(
                                                        configService.getSsmParameter(
                                                                BACKEND_SESSION_TIMEOUT))));
    }

    @Tracing
    private Map<IpvJourneyTypes, StateMachine> loadStateMachines(
            List<IpvJourneyTypes> journeyTypes,
            StateMachineInitializerMode stateMachineInitializerMode)
            throws IOException {
        EnumMap<IpvJourneyTypes, StateMachine> stateMachinesMap =
                new EnumMap<>(IpvJourneyTypes.class);
        for (IpvJourneyTypes journeyType : journeyTypes) {
            stateMachinesMap.put(
                    journeyType,
                    new StateMachine(
                            new StateMachineInitializer(journeyType, stateMachineInitializerMode)));
        }
        return stateMachinesMap;
    }

    private void sendMitigationStartAuditEvent(
            String ipvSessionId, String ipAddress, ClientOAuthSessionItem clientOAuthSessionItem)
            throws SqsException {
        var auditEventUser =
                new AuditEventUser(
                        clientOAuthSessionItem.getUserId(),
                        ipvSessionId,
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_MITIGATION_START,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));
    }
}
