package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.Map;

@SuppressWarnings({"javaarchitecture:S7027"}) // Circular dependency with implementations
@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicEvent.class),
    @JsonSubTypes.Type(value = ExitNestedJourneyEvent.class)
})
public interface Event {

    void initialize(
            String name, Map<String, State> states, Map<String, Event> nestedJourneyExitEvents);
}
