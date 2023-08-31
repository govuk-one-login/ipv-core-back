package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.StepResponse;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BasicState implements State {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String ATTEMPT_RECOVERY_EVENT = "attempt-recovery";
    private String name;
    private String parent;
    private BasicState parentObj;
    private StepResponse response;
    private Map<String, Event> events = new HashMap<>();

    @Override
    public State transition(String eventName, String startState, JourneyContext journeyContext)
            throws UnknownEventException {
        if (ATTEMPT_RECOVERY_EVENT.equals(eventName)) {
            return this;
        }

        return getEvent(eventName)
                .orElseThrow(
                        () ->
                                new UnknownEventException(
                                        String.format(
                                                "Unknown event provided to '%s' state: '%s'",
                                                name, eventName)))
                .resolve(journeyContext);
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
