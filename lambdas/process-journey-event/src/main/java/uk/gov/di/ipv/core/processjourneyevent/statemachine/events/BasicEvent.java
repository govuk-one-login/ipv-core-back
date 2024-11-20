package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import com.amazonaws.util.StringUtils;
import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.JourneyChangeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;

@Data
public class BasicEvent implements Event {
    private static final Logger LOGGER = LogManager.getLogger();
    private String name;
    private String targetJourney;
    private String targetState;
    private String targetEntryEvent;
    private State targetStateObj;
    private LinkedHashMap<String, Event> checkIfDisabled;
    private LinkedHashMap<String, Event> checkFeatureFlag;
    private LinkedHashMap<String, Event> checkJourneyContext;
    private List<AuditEventTypes> auditEvents = new ArrayList<>();
    private LinkedHashMap<String, String> auditContext = new LinkedHashMap<>();

    public TransitionResult resolve(JourneyContext journeyContext) throws UnknownEventException {
        if (checkIfDisabled != null) {
            Optional<String> firstDisabledCri =
                    checkIfDisabled.keySet().stream()
                            .filter(
                                    id ->
                                            !journeyContext
                                                    .configService()
                                                    .getBooleanParameter(
                                                            CREDENTIAL_ISSUER_ENABLED, id))
                            .findFirst();
            if (firstDisabledCri.isPresent()) {
                String disabledCriId = firstDisabledCri.get();
                LOGGER.info("CRI with ID '{}' is disabled. Using alternative event", disabledCriId);
                return checkIfDisabled.get(disabledCriId).resolve(journeyContext);
            }
        }
        if (checkJourneyContext != null && !StringUtils.isNullOrEmpty(journeyContext.name())) {
            Optional<String> matchingContext =
                    checkJourneyContext.keySet().stream()
                            .filter(ctx -> ctx.equals(journeyContext.name()))
                            .findFirst();
            if (matchingContext.isPresent()) {
                String contextValue = matchingContext.get();
                LOGGER.info("Matching context '{}' is set. Using alternative event", contextValue);
                return checkJourneyContext.get(contextValue).resolve(journeyContext);
            }
        }
        if (checkFeatureFlag != null) {
            Optional<String> firstFeatureFlag =
                    checkFeatureFlag.keySet().stream()
                            .filter(
                                    featureFlagValue ->
                                            journeyContext
                                                    .configService()
                                                    .enabled(featureFlagValue))
                            .findFirst();
            if (firstFeatureFlag.isPresent()) {
                String featureFlagValue = firstFeatureFlag.get();
                LOGGER.info("Feature flag '{}' is set. Using alternative event", featureFlagValue);
                return checkFeatureFlag.get(featureFlagValue).resolve(journeyContext);
            }
        }
        return new TransitionResult(targetStateObj, auditEvents, auditContext, targetEntryEvent);
    }

    @Override
    public void initialize(
            String name, Map<String, State> states, Map<String, Event> nestedJourneyExitEvents) {
        this.name = name;
        if (targetJourney != null) {
            this.targetStateObj =
                    new JourneyChangeState(IpvJourneyTypes.valueOf(targetJourney), targetState);
        } else if (targetState != null) {
            this.targetStateObj = states.get(targetState);
        }
        if (checkIfDisabled != null) {
            checkIfDisabled.forEach(
                    (eventName, event) ->
                            initialiseEvent(event, eventName, states, nestedJourneyExitEvents));
        }
        if (checkFeatureFlag != null) {
            checkFeatureFlag.forEach(
                    (eventName, event) ->
                            initialiseEvent(event, eventName, states, nestedJourneyExitEvents));
        }
        if (checkJourneyContext != null) {
            checkJourneyContext.forEach(
                    (eventName, event) ->
                            initialiseEvent(event, eventName, states, nestedJourneyExitEvents));
        }
    }

    private void initialiseEvent(
            Event event,
            String eventName,
            Map<String, State> states,
            Map<String, Event> nestedJourneyExitEvents) {
        if (event instanceof ExitNestedJourneyEvent exitNestedJourneyEvent) {
            exitNestedJourneyEvent.setNestedJourneyExitEvents(nestedJourneyExitEvents);
        } else {
            event.initialize(eventName, states, nestedJourneyExitEvents);
        }
    }
}
