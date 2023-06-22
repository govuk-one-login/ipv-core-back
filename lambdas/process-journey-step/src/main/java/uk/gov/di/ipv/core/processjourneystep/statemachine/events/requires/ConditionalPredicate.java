package uk.gov.di.ipv.core.processjourneystep.statemachine.events.requires;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({@JsonSubTypes.Type(value = EnabledCris.class, name = "enabledCris")})
public interface ConditionalPredicate {
    public boolean check();
}
