package uk.gov.di.ipv.core.processjourneystep.statemachine;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;

import java.util.Map;

@Data
public class SubJourneyDefinition {
    private Map<String, Event> entryEvents;
    private Map<String, State> subJourneyStates;
}
