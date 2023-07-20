package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;

import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicEvent.class),
    @JsonSubTypes.Type(value = ExitEvent.class)
})
public interface Event {
    State resolve(JourneyContext journeyContext);

    void initialize(String name, Map<String, State> states);
}
