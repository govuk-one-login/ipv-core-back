package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;

import java.util.Map;

@Data
public class ExitEvent implements Event {

    private String exitEventToEmit;
    private Map<String, Event> subJourneyExitEvents;

    @Override
    public State resolve(JourneyContext journeyContext) {
        return subJourneyExitEvents.get(exitEventToEmit).resolve(journeyContext);
    }

    @Override
    public void initialize(String name, Map<String, State> states) {
        throw new UnsupportedOperationException("We don't do that");
    }
}
