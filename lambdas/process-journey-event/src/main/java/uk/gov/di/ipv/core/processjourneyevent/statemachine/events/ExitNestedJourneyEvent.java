package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.Map;

@Data
public class ExitNestedJourneyEvent implements Event {

    private String exitEventToEmit;
    private Map<String, Event> nestedJourneyExitEvents;

    @Override
    public void initialize(
            String name, Map<String, State> states, Map<String, Event> nestedJourneyExitEvents) {
        throw new UnsupportedOperationException(
                "Initialize of ExitNestedJourneyEvent not supported");
    }
}
