package uk.gov.di.ipv.core.statemachine;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = JourneyResponse.class, name = "journey"),
        @JsonSubTypes.Type(value = PageResponse.class, name = "page")})
public interface JourneyStepResponse {
    String value();
}
