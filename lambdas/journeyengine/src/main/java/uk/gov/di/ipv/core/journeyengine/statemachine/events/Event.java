package uk.gov.di.ipv.core.journeyengine.statemachine.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.journeyengine.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.journeyengine.statemachine.responses.JourneyContext;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({@JsonSubTypes.Type(value = BasicEvent.class, name = "basic")})
public interface Event {
    StateMachineResult resolve(JourneyContext journeyContext);
}
