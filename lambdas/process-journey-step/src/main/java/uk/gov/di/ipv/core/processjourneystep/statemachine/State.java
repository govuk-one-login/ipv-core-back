package uk.gov.di.ipv.core.processjourneystep.statemachine;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class State {
    private String name;
    private State parent;
    private Map<String, Event> events = new HashMap<>();

    public State(String name) {
        this.name = name;
    }

    public StateMachineResult transition(String eventName, JourneyContext journeyContext)
            throws UnknownEventException {
        var event = getEvent(eventName);
        if (event.isPresent()) {
            return event.get().resolve(journeyContext);
        }
        throw new UnknownEventException(
                String.format("Unknown event provided to '%s' state: '%s'", name, eventName));
    }

    private Optional<Event> getEvent(String eventName) {
        var event = events.get(eventName);
        if (event == null && parent != null) {
            return parent.getEvent(eventName);
        }
        return Optional.ofNullable(event);
    }
}
