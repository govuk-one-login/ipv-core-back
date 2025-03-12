package uk.gov.di.ipv.core.processjourneyevent;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
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
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.NestedJourneyTypes;
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
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.ProcessStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.StepResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_EVENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_TYPE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_USER_STATE;
import static uk.gov.di.ipv.core.library.journeys.Events.BUILD_CLIENT_OAUTH_RESPONSE_EVENT;

public class ProcessJourneyEventHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CURRENT_PAGE = "currentPage";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";
    private static final String NEXT_EVENT = "next";
    private static final StepResponse BUILD_CLIENT_OAUTH_RESPONSE =
            new ProcessStepResponse(BUILD_CLIENT_OAUTH_RESPONSE_EVENT, null);
    private static final String BACK_EVENT = "back";
    private static final String TICF_CRI_LAMBDA = "call-ticf-cri";
    private static final String CHECK_COI_LAMBDA = "check-coi";

    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final Map<IpvJourneyTypes, StateMachine> stateMachines;
    private final EvcsService evcsService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public ProcessJourneyEventHandler(
            AuditService auditService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            List<IpvJourneyTypes> journeyTypes,
            StateMachineInitializerMode stateMachineInitializerMode,
            List<String> nestedJourneyTypes,
            EvcsService evcsService)
            throws IOException {
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.configService = configService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.stateMachines =
                loadStateMachines(journeyTypes, stateMachineInitializerMode, nestedJourneyTypes);
        this.evcsService = evcsService;
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
        this.evcsService = new EvcsService(configService);
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Object> handleRequest(JourneyRequest journeyRequest, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            String journeyEvent = RequestHelper.getJourneyEvent(journeyRequest);

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
        } catch (EvcsServiceException | CredentialParseException e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_EVCS_RESPONSE);
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
            throws JourneyEngineException, EvcsServiceException, CredentialParseException {
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
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                                    "Invalid journey state encountered, failed to execute journey engine step.",
                                    e)
                            .with(
                                    LOG_USER_STATE.getFieldName(),
                                    ipvSessionItem.getState().state()));
            throw new JourneyEngineException();
        } catch (UnknownEventException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                                    "Invalid journey event provided, failed to execute journey engine step.",
                                    e)
                            .with(LOG_JOURNEY_EVENT.getFieldName(), journeyEvent));
            throw new JourneyEngineException();
        } catch (StateMachineNotFoundException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                                    "State machine not found for journey type, failed to execute journey engine step",
                                    e)
                            .with(LOG_JOURNEY_EVENT.getFieldName(), journeyEvent)
                            .with(
                                    LOG_JOURNEY_TYPE.getFieldName(),
                                    ipvSessionItem.getState().subJourney().name()));
            throw new JourneyEngineException();
        }
    }

    @SuppressWarnings("java:S3776") // Cognitive Complexity of methods should not be too high
    private State executeStateTransition(
            JourneyState initialJourneyState,
            IpvSessionItem ipvSessionItem,
            String journeyEvent,
            String currentPage,
            AuditEventUser auditEventUser,
            String deviceInformation,
            ClientOAuthSessionItem clientOAuthSessionItem)
            throws StateMachineNotFoundException, UnknownEventException, UnknownStateException,
                    EvcsServiceException, CredentialParseException {

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

        var result =
                stateMachine.transition(
                        initialJourneyState.state(),
                        journeyEvent,
                        new JourneyContext(configService, ipvSessionItem.getJourneyContext()),
                        currentPage);

        if (!isNullOrEmpty(result.auditEvents())) {
            for (var auditEventType : result.auditEvents()) {
                sendJourneyAuditEvent(
                        auditEventType, result.auditContext(), auditEventUser, deviceInformation);
            }
        }

        // Special case to skip TICF CRI if it has been disabled,
        // to save us defining lots of fallback routes in the journey map
        if (result.state() instanceof BasicState basicState
                && basicState.getResponse() instanceof ProcessStepResponse processResponse
                && TICF_CRI_LAMBDA.equals(processResponse.getLambda())
                && !configService.getBooleanParameter(
                        CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId())) {
            LOGGER.info(LogHelper.buildLogMessage("Skipping disabled TICF CRI state"));
            return executeStateTransition(
                    new JourneyState(basicState.getJourneyType(), basicState.getName()),
                    ipvSessionItem,
                    NEXT_EVENT,
                    null,
                    auditEventUser,
                    deviceInformation,
                    clientOAuthSessionItem);
        }

        // Special case to skip COI check if the user does not already have an identity
        if (result.state() instanceof BasicState basicState
                && basicState.getResponse() instanceof ProcessStepResponse processResponse
                && CHECK_COI_LAMBDA.equals(processResponse.getLambda())
                && !hasExistingIdentity(clientOAuthSessionItem)) {
            LOGGER.info(LogHelper.buildLogMessage("Skipping COI check - no existing identity"));
            return executeStateTransition(
                    new JourneyState(basicState.getJourneyType(), basicState.getName()),
                    ipvSessionItem,
                    "coi-check-passed",
                    null,
                    auditEventUser,
                    deviceInformation,
                    clientOAuthSessionItem);
        }

        if (result.state() instanceof BasicState basicState) {
            ipvSessionItem.pushState(
                    new JourneyState(basicState.getJourneyType(), basicState.getName()));
            var ctx = basicState.getJourneyContext();
            if (ctx != null && !ctx.isEmpty()) {
                ipvSessionItem.setJourneyContext(ctx);
            }
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

    private boolean hasExistingIdentity(ClientOAuthSessionItem clientOAuthSessionItem)
            throws EvcsServiceException, CredentialParseException {
        return !evcsService
                .getVerifiableCredentials(
                        clientOAuthSessionItem.getUserId(),
                        clientOAuthSessionItem.getEvcsAccessToken(),
                        CURRENT)
                .isEmpty();
    }

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
                && Instant.parse(ipvSessionItem.getCreationDateTime())
                        .isBefore(
                                Instant.now()
                                        .minusSeconds(
                                                configService.getLongParameter(
                                                        BACKEND_SESSION_TIMEOUT)));
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
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        getAuditExtensions(auditEventType, auditContext),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }

    private AuditExtensions getAuditExtensions(
            AuditEventTypes auditEventType, Map<String, String> auditContext) {
        return switch (auditEventType) {
            case IPV_MITIGATION_START -> new AuditExtensionMitigationType(
                    auditContext.get("mitigationType"));
            case IPV_USER_DETAILS_UPDATE_SELECTED -> new AuditExtensionUserDetailsUpdateSelected(
                    Arrays.stream(auditContext.get("updateFields").split(","))
                            .map(String::trim)
                            .toList(),
                    Boolean.parseBoolean(auditContext.get("updateSupported")));
            case IPV_USER_DETAILS_UPDATE_END -> new AuditExtensionSuccessful(
                    Boolean.parseBoolean(auditContext.get("successful")));
            default -> null;
        };
    }

    private void sendSubJourneyStartAuditEvent(
            AuditEventUser auditEventUser, IpvJourneyTypes journeyType, String deviceInformation) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_SUBJOURNEY_START,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
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
}
