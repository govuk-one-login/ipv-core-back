package uk.gov.di.ipv.core.processjourneystep.statemachine.states;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicState.class),
    @JsonSubTypes.Type(value = NestedJourneyInvokeState.class),
})
public interface State {
    State transition(String eventName, String startState, JourneyContext journeyContext)
            throws UnknownEventException, UnknownStateException;

    String getName();

    void setName(String name);
}
