package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicEvent.class, name = "basic"),
    @JsonSubTypes.Type(value = FeatureSetEvent.class, name = "featureSet"),
    @JsonSubTypes.Type(value = CriEvent.class, name = "cri"),
    @JsonSubTypes.Type(value = ConditionalEvent.class, name = "conditional")
})
public interface Event {
    StateMachineResult resolve(JourneyContext journeyContext);
}
