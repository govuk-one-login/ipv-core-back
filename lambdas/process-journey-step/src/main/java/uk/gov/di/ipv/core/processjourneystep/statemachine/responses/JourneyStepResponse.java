package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = JourneyResponse.class, name = "journey"),
    @JsonSubTypes.Type(value = PageResponse.class, name = "page"),
    @JsonSubTypes.Type(value = CriResponse.class, name = "cri")
})
public interface JourneyStepResponse {
    Map<String, String> value(ConfigurationService configurationService);

    Map<String, String> value(String id);
}
