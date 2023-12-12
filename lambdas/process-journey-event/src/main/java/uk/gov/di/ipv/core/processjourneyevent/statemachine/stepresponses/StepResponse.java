package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = JourneyStepResponse.class, name = "journey"),
    @JsonSubTypes.Type(value = PageStepResponse.class, name = "page"),
    @JsonSubTypes.Type(value = ErrorStepResponse.class, name = "error"),
    @JsonSubTypes.Type(value = CriStepResponse.class, name = "cri"),
    @JsonSubTypes.Type(value = ProcessStepResponse.class, name = "process")
})
public interface StepResponse {
    Map<String, Object> value();

    Boolean getMitigationStart();
}
