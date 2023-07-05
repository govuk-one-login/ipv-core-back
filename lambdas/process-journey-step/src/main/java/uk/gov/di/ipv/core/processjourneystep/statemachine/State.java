package uk.gov.di.ipv.core.processjourneystep.statemachine;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyStepResponse;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class State {
    public static final String ATTEMPT_RECOVERY_EVENT = "attempt-recovery";
    private String name;
    private String parent;
    private State parentObj;
    private JourneyStepResponse response;
    private Map<String, Event> events = new HashMap<>();

    public State transition(String eventName, JourneyContext journeyContext)
            throws UnknownEventException {

        if (ATTEMPT_RECOVERY_EVENT.equals(eventName)) {
            return this;
        }

        var event = getEvent(eventName);
        if (event.isPresent()) {
            return event.get().resolve(journeyContext);
        }
        throw new UnknownEventException(
                String.format("Unknown event provided to '%s' state: '%s'", name, eventName));
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
