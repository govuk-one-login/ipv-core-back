package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicEvent.class, name = "basic"),
    @JsonSubTypes.Type(value = CriEvent.class, name = "cri")
})
public interface Event {
    StateMachineResult resolve(JourneyContext journeyContext);
}
