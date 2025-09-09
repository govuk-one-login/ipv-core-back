package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import lombok.Data;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.JourneyChangeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
public class BasicEvent implements Event {
    private String name;
    private String targetJourney;
    private String targetState;
    private String targetEntryEvent;
    private String journeyContextToSet;
    private String journeyContextToUnset;
    private State targetStateObj;
    private LinkedHashMap<String, Event> checkIfDisabled;
    private LinkedHashMap<String, Event> checkFeatureFlag;
    private LinkedHashMap<String, Event> checkJourneyContext;
    private List<AuditEventTypes> auditEvents;
    private LinkedHashMap<String, String> auditContext;
    private LinkedHashMap<String, Event> checkMitigation;

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
        if (checkMitigation != null) {
            checkMitigation.forEach(
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
