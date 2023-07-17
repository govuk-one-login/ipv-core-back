package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({@JsonSubTypes.Type(value = BasicEvent.class, name = "basic")})
public interface Event {
    State resolve(JourneyContext journeyContext);

    void initialize(String name, Map<String, State> states);
}
