package uk.gov.di.ipv.core.processjourneyevent;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionMitigationType;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionSubjourneyType;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionSuccessful;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionUserDetailsUpdateSelected;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensions;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.NestedJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachine;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializer;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializerMode;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolver;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.StateMachineNotFoundException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.JourneyChangeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.ProcessStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.StepResponse;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_EVENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_TYPE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_USER_STATE;
import static uk.gov.di.ipv.core.library.journeys.Events.BUILD_CLIENT_OAUTH_RESPONSE_EVENT;
import static uk.gov.di.ipv.core.library.journeys.Events.PROBLEM_DIFFERENT_BROWSER_PAGE_EVENT;

public class ProcessJourneyEventHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CURRENT_PAGE = "currentPage";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";
    private static final String NEXT_EVENT = "next";
    private static final StepResponse BUILD_CLIENT_OAUTH_RESPONSE =
            new ProcessStepResponse(BUILD_CLIENT_OAUTH_RESPONSE_EVENT, null);
    private static final StepResponse PROBLEM_DIFFERENT_BROWSER_PAGE_RESPONSE =
            new PageStepResponse("problem-different-browser", null, null);
    private static final String BACK_EVENT = "back";

    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final Map<IpvJourneyTypes, StateMachine> stateMachines;
    private final CimitUtilityService cimitUtilityService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public ProcessJourneyEventHandler(
            AuditService auditService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            List<IpvJourneyTypes> journeyTypes,
            StateMachineInitializerMode stateMachineInitializerMode,
            List<String> nestedJourneyTypes,
            CimitUtilityService cimitUtilityService)
            throws IOException {
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.configService = configService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.stateMachines =
                loadStateMachines(journeyTypes, stateMachineInitializerMode, nestedJourneyTypes);
        this.cimitUtilityService = cimitUtilityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessJourneyEventHandler() throws IOException {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessJourneyEventHandler(ConfigService configService) throws IOException {
        this.configService = configService;
        this.auditService = AuditService.create(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);

        var nestedJourneyTypes =
                Stream.of(NestedJourneyTypes.values())
                        .map(NestedJourneyTypes::getJourneyName)
                        .toList();

        this.stateMachines =
                loadStateMachines(
                        List.of(IpvJourneyTypes.values()),
                        StateMachineInitializerMode.STANDARD,
                        nestedJourneyTypes);
        this.cimitUtilityService = new CimitUtilityService(configService);
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public Map<String, Object> handleRequest(JourneyRequest journeyRequest, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            String journeyEvent = RequestHelper.getJourneyEvent(journeyRequest);

            // Special case
            // Handle route to problem-different-browser page directly as user will
            // have a missing ipv-session header
            if (journeyEvent.equals(PROBLEM_DIFFERENT_BROWSER_PAGE_EVENT)) {
                LOGGER.info(
                        LogHelper.buildLogMessage("Directing user to cross-browser problem page"));
                return PROBLEM_DIFFERENT_BROWSER_PAGE_RESPONSE.value();
            }

            // Special case
            // Handle route direct back to RP (used for recoverable timeouts and cross browser
            // callbacks).
            // Users sending this event may not have a valid IPV session
            if (journeyEvent.equals(BUILD_CLIENT_OAUTH_RESPONSE_EVENT)) {
                LOGGER.info(LogHelper.buildLogMessage("Returning end session response directly"));
                return BUILD_CLIENT_OAUTH_RESPONSE.value();
            }

            // Extract variables
            String ipvSessionId = RequestHelper.getIpvSessionId(journeyRequest);
            String ipAddress = RequestHelper.getIpAddress(journeyRequest);
            String deviceInformation = journeyRequest.getDeviceInformation();
            String currentPage = RequestHelper.getJourneyParameter(journeyRequest, CURRENT_PAGE);
            configService.setFeatureSet(RequestHelper.getFeatureSet(journeyRequest));

            // Get/ set session items/ config
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            // Attach variables to logs
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            var auditEventUser =
                    new AuditEventUser(
                            clientOAuthSessionItem.getUserId(),
                            ipvSessionId,
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            ipAddress);

            StepResponse stepResponse =
                    executeJourneyEvent(
                            journeyEvent,
                            ipvSessionItem,
                            auditEventUser,
                            deviceInformation,
                            currentPage,
                            clientOAuthSessionItem);

            ipvSessionService.updateIpvSession(ipvSessionItem);

            return stepResponse.value();
        } catch (HttpResponseExceptionWithErrorBody e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    e.getResponseCode(), e.getErrorResponse());
        } catch (JourneyEngineException e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_JOURNEY_ENGINE_STEP);
        } catch (IpvSessionNotFoundException e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.IPV_SESSION_NOT_FOUND);
        } catch (UncheckedIOException e) {
            // Temporary mitigation to force lambda instance to crash and restart by explicitly
            // exiting the program on fatal IOException - see PYIC-8220 and incident INC0014398.
            LOGGER.error("Crashing on UncheckedIOException", e);
            System.exit(1);
            return null;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private StepResponse executeJourneyEvent(
            String journeyEvent,
            IpvSessionItem ipvSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation,
            String currentPage,
            ClientOAuthSessionItem clientOAuthSessionItem)
            throws JourneyEngineException {
        if (sessionIsNewlyExpired(ipvSessionItem)) {
            updateUserSessionForTimeout(ipvSessionItem, auditEventUser, deviceInformation);
            journeyEvent = NEXT_EVENT;
        }

        var currentJourneyState = ipvSessionItem.getState();

        try {
            var newState =
                    executeStateTransition(
                            currentJourneyState,
                            ipvSessionItem,
                            journeyEvent,
                            currentPage,
                            auditEventUser,
                            deviceInformation,
                            clientOAuthSessionItem);

            while (newState instanceof JourneyChangeState journeyChangeState) {
                LOGGER.info(
                        LogHelper.buildLogMessage("Transitioned to new journey type")
                                .with(
                                        LOG_JOURNEY_TYPE.getFieldName(),
                                        journeyChangeState.getJourneyType())
                                .with(
                                        LOG_USER_STATE.getFieldName(),
                                        journeyChangeState.getInitialState()));

                sendSubJourneyStartAuditEvent(
                        auditEventUser, journeyChangeState.getJourneyType(), deviceInformation);
                newState =
                        executeStateTransition(
                                journeyStateFrom(journeyChangeState),
                                ipvSessionItem,
                                NEXT_EVENT,
                                null,
                                auditEventUser,
                                deviceInformation,
                                clientOAuthSessionItem);
            }

            logStateChange(currentJourneyState, journeyEvent, ipvSessionItem);

            clearOauthSessionIfExists(ipvSessionItem);

            return ((BasicState) newState).getResponse();
        } catch (UnknownStateException e) {
            logErrorWithCurrentJourneyDetails(
                    "Invalid journey state encountered, failed to execute journey engine step.",
                    e,
                    journeyEvent,
                    ipvSessionItem.getState());
            throw new JourneyEngineException();
        } catch (UnknownEventException e) {
            logWithCurrentJourneyDetails(
                    Level.WARN,
                    "Invalid journey event provided, failed to execute journey engine step.",
                    e,
                    journeyEvent,
                    ipvSessionItem.getState());
            throw new JourneyEngineException();
        } catch (StateMachineNotFoundException e) {
            logErrorWithCurrentJourneyDetails(
                    "State machine not found for journey type, failed to execute journey engine step",
                    e,
                    journeyEvent,
                    ipvSessionItem.getState());
            throw new JourneyEngineException();
        } catch (JourneyEngineException e) {
            logErrorWithCurrentJourneyDetails(
                    e.getMessage(), e, journeyEvent, ipvSessionItem.getState());
            throw e;
        }
    }

    private State executeStateTransition(
            JourneyState initialJourneyState,
            IpvSessionItem ipvSessionItem,
            String journeyEvent,
            String currentPage,
            AuditEventUser auditEventUser,
            String deviceInformation,
            ClientOAuthSessionItem clientOAuthSessionItem)
            throws StateMachineNotFoundException,
                    UnknownEventException,
                    UnknownStateException,
                    JourneyEngineException {

        StateMachine stateMachine = stateMachines.get(initialJourneyState.subJourney());
        if (stateMachine == null) {
            throw new StateMachineNotFoundException(
                    String.format(
                            "State machine not found for journey type: '%s'",
                            initialJourneyState.subJourney()));
        }
        LOGGER.debug(
                LogHelper.buildLogMessage(
                        String.format(
                                "Found state machine for journey type: %s",
                                initialJourneyState.subJourney())));

        if (BACK_EVENT.equals(journeyEvent) && !isBackEventDefinedOnState(initialJourneyState)) {
            return handleBackEvent(ipvSessionItem, initialJourneyState);
        }

        var eventResolver = new EventResolver(cimitUtilityService, configService);

        var result =
                stateMachine.transition(
                        initialJourneyState.state(),
                        journeyEvent,
                        currentPage,
                        new EventResolveParameters(
                                ipvSessionItem.getActiveJourneyContexts(),
                                ipvSessionItem,
                                clientOAuthSessionItem),
                        eventResolver);

        if (!isNullOrEmpty(result.auditEvents())) {
            for (var auditEventType : result.auditEvents()) {
                sendJourneyAuditEvent(
                        auditEventType, result.auditContext(), auditEventUser, deviceInformation);
            }
        }

        if (!isNullOrEmpty(result.journeyContextsToSet())) {
            result.journeyContextsToSet().forEach(ipvSessionItem::setJourneyContext);
        }
        if (!isNullOrEmpty(result.journeyContextsToUnset())) {
            result.journeyContextsToUnset().forEach(ipvSessionItem::unsetJourneyContext);
        }

        if (result.state() instanceof BasicState basicState) {
            ipvSessionItem.pushState(
                    new JourneyState(basicState.getJourneyType(), basicState.getName()));
        }

        return result.state();
    }

    private State handleBackEvent(IpvSessionItem ipvSessionItem, JourneyState initialJourneyState)
            throws UnknownEventException, StateMachineNotFoundException, UnknownStateException {
        var previousJourneyState = ipvSessionItem.getPreviousState();

        if (isPageState(initialJourneyState) && isPageState(previousJourneyState)) {
            var state = journeyStateToBasicState(previousJourneyState);
            var skipBackResponse =
                    ((PageStepResponse) ((BasicState) state).getResponse()).getSkipBack();

            if (Boolean.TRUE.equals(skipBackResponse)) {
                ipvSessionItem.popState();
                previousJourneyState = ipvSessionItem.getPreviousState();
            }
            ipvSessionItem.popState();

            return journeyStateToBasicState(previousJourneyState);
        }

        throw new UnknownEventException(
                String.format("Back event provided to state: '%s'", initialJourneyState.state()));
    }

    // This logging is depended on for user traffic data in the journey map
    private void logStateChange(
            JourneyState oldJourneyState, String journeyEvent, IpvSessionItem ipvSessionItem) {
        var newJourneyState = ipvSessionItem.getState();
        var message =
                new StringMapMessage()
                        .with("journeyEngine", "State transition")
                        .with("event", journeyEvent)
                        .with("from", oldJourneyState.state())
                        .with("to", newJourneyState.state())
                        .with("fromJourney", oldJourneyState.subJourney())
                        .with("toJourney", newJourneyState.subJourney());
        LOGGER.info(message);
    }

    private void clearOauthSessionIfExists(IpvSessionItem ipvSessionItem) {
        if (ipvSessionItem.getCriOAuthSessionId() != null) {
            ipvSessionItem.setCriOAuthSessionId(null);
        }
    }

    private void updateUserSessionForTimeout(
            IpvSessionItem ipvSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        var oldJourneyState = ipvSessionItem.getState();

        ipvSessionItem.setErrorCode(OAuth2Error.ACCESS_DENIED.getCode());
        ipvSessionItem.setErrorDescription(OAuth2Error.ACCESS_DENIED.getDescription());
        ipvSessionItem.pushState(new JourneyState(SESSION_TIMEOUT, CORE_SESSION_TIMEOUT_STATE));

        logStateChange(oldJourneyState, "timeout", ipvSessionItem);
        sendSubJourneyStartAuditEvent(auditEventUser, SESSION_TIMEOUT, deviceInformation);
    }

    private boolean sessionIsNewlyExpired(IpvSessionItem ipvSessionItem) {
        return (!SESSION_TIMEOUT.equals(ipvSessionItem.getState().subJourney()))
                && ipvSessionService.checkIfSessionExpired(ipvSessionItem);
    }

    private Map<IpvJourneyTypes, StateMachine> loadStateMachines(
            List<IpvJourneyTypes> journeyTypes,
            StateMachineInitializerMode stateMachineInitializerMode,
            List<String> nestedJourneyTypes)
            throws IOException {
        EnumMap<IpvJourneyTypes, StateMachine> stateMachinesMap =
                new EnumMap<>(IpvJourneyTypes.class);
        for (IpvJourneyTypes journeyType : journeyTypes) {
            stateMachinesMap.put(
                    journeyType,
                    new StateMachine(
                            new StateMachineInitializer(
                                    journeyType, stateMachineInitializerMode, nestedJourneyTypes)));
        }
        return stateMachinesMap;
    }

    private void sendJourneyAuditEvent(
            AuditEventTypes auditEventType,
            Map<String, String> auditContext,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        auditEventType,
                        configService.getComponentId(),
                        auditEventUser,
                        getAuditExtensions(auditEventType, auditContext),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }

    private AuditExtensions getAuditExtensions(
            AuditEventTypes auditEventType, Map<String, String> auditContext) {
        return switch (auditEventType) {
            case IPV_MITIGATION_START ->
                    new AuditExtensionMitigationType(auditContext.get("mitigationType"));
            case IPV_USER_DETAILS_UPDATE_SELECTED ->
                    new AuditExtensionUserDetailsUpdateSelected(
                            Arrays.stream(auditContext.get("updateFields").split(","))
                                    .map(String::trim)
                                    .toList(),
                            Boolean.parseBoolean(auditContext.get("updateSupported")));
            case IPV_USER_DETAILS_UPDATE_END ->
                    new AuditExtensionSuccessful(
                            Boolean.parseBoolean(auditContext.get("successful")));
            default -> null;
        };
    }

    private void sendSubJourneyStartAuditEvent(
            AuditEventUser auditEventUser, IpvJourneyTypes journeyType, String deviceInformation) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_SUBJOURNEY_START,
                        configService.getComponentId(),
                        auditEventUser,
                        new AuditExtensionSubjourneyType(journeyType),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }

    private boolean isPageState(JourneyState journeyState)
            throws StateMachineNotFoundException, UnknownStateException {
        StateMachine stateMachine = stateMachines.get(journeyState.subJourney());
        if (stateMachine == null) {
            throw new StateMachineNotFoundException(
                    String.format(
                            "State machine not found for journey type: '%s'",
                            journeyState.subJourney()));
        }
        return stateMachine.isPageState(journeyState);
    }

    private State journeyStateToBasicState(JourneyState journeyState) {
        return stateMachines.get(journeyState.subJourney()).getState(journeyState.state());
    }

    private JourneyState journeyStateFrom(JourneyChangeState journeyChangeState) {
        return new JourneyState(
                journeyChangeState.getJourneyType(), journeyChangeState.getInitialState());
    }

    private boolean isBackEventDefinedOnState(JourneyState journeyState) {
        return stateMachines.get(journeyState.subJourney()).getState(journeyState.state())
                        instanceof BasicState basicState
                && basicState.getEvents().containsKey(BACK_EVENT);
    }

    private void logWithCurrentJourneyDetails(
            Level level,
            String message,
            Exception e,
            String journeyEvent,
            JourneyState journeyState) {
        LOGGER.log(
                level,
                LogHelper.buildErrorMessage(message, e)
                        .with(LOG_JOURNEY_EVENT.getFieldName(), journeyEvent)
                        .with(LOG_USER_STATE.getFieldName(), journeyState.state())
                        .with(LOG_JOURNEY_TYPE.getFieldName(), journeyState.subJourney().name()));
    }

    private void logErrorWithCurrentJourneyDetails(
            String message, Exception e, String journeyEvent, JourneyState journeyState) {
        logWithCurrentJourneyDetails(Level.ERROR, message, e, journeyEvent, journeyState);
    }
}
