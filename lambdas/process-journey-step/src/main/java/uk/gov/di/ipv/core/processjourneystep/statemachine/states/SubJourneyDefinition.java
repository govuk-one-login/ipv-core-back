package uk.gov.di.ipv.core.processjourneystep.statemachine.states;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;

import java.util.Map;

@Data
public class SubJourneyDefinition {
    private Map<String, Event> entryEvents;
    private Map<String, State> subJourneyStates;
}
