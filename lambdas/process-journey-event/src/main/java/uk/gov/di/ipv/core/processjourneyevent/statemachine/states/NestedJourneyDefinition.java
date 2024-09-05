package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;

import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class NestedJourneyDefinition {
    private Map<String, Event> entryEvents;
    private Map<String, State> nestedJourneyStates;
}
