package uk.gov.di.ipv.core.processjourneystep.statemachine.events.requiredNotMet;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({@JsonSubTypes.Type(value = FirstEnabled.class, name = "firstEnabled")})
public interface ConditionalRequiredNotMet {
    public StateMachineResult resolve(JourneyContext journeyContext);
}
