package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;

import java.util.Map;

@Data
public class NestedJourneyDefinition {
    private Map<String, Event> entryEvents;
    private Map<String, State> nestedJourneyStates;
}
