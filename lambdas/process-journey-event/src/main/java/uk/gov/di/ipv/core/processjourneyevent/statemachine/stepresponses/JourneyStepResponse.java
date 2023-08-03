package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = JourneyResponse.class, name = "journey"),
    @JsonSubTypes.Type(value = PageStepResponse.class, name = "page"),
    @JsonSubTypes.Type(value = ErrorStepResponse.class, name = "error"),
    @JsonSubTypes.Type(value = CriStepResponse.class, name = "cri")
})
public interface JourneyStepResponse {
    Map<String, Object> value();
}
