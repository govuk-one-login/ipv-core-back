package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;

import java.util.Map;

@Data
public class ExitNestedJourneyEvent implements Event {

    private String exitEventToEmit;
    private Map<String, Event> nestedJourneyExitEvents;

    @Override
    public State resolve(JourneyContext journeyContext) throws UnknownEventException {
        Event event = nestedJourneyExitEvents.get(exitEventToEmit);
        if (event == null) {
            throw new UnknownEventException("Event '%s' not found in nested journey's exit events");
        }
        return event.resolve(journeyContext);
    }

    @Override
    public void initialize(String name, Map<String, State> states) {
        throw new UnsupportedOperationException(
                "Initialize of ExitNestedJourneyEvent not supported");
    }
}
