package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolver;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.StepResponse;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BasicState implements State {
    private static final String ATTEMPT_RECOVERY_EVENT = "attempt-recovery";

    private String name;
    private String parent;
    private BasicState parentObj;
    private StepResponse response;
    private Map<String, Event> events = new HashMap<>();
    private IpvJourneyTypes journeyType;

    @Override
    public TransitionResult transition(
            String eventName,
            String startState,
            EventResolveParameters eventResolveParameters,
            EventResolver eventResolver)
            throws UnknownEventException, UnknownStateException, JourneyEngineException {
        // Special recovery event
        if (ATTEMPT_RECOVERY_EVENT.equals(eventName)) {
            return new TransitionResult(this);
        }

        var event =
                getEvent(eventName)
                        .orElseThrow(
                                () ->
                                        new UnknownEventException(
                                                String.format(
                                                        "Unknown event provided to '%s' state: '%s'",
                                                        name, eventName)));
        return eventResolver.resolve(event, eventResolveParameters);
    }

    private Optional<Event> getEvent(String eventName) {
        var event = events.get(eventName);
        if (event == null && parentObj != null) {
            return parentObj.getEvent(eventName);
        }
        return Optional.ofNullable(event);
    }

    @Override
    public String toString() {
        return this.name;
    }
}
