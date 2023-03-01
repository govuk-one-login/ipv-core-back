package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = JourneyResponse.class, name = "journey"),
    @JsonSubTypes.Type(value = PageResponse.class, name = "page"),
    @JsonSubTypes.Type(value = ErrorResponse.class, name = "error"),
    @JsonSubTypes.Type(value = CriResponse.class, name = "cri")
})
public interface JourneyStepResponse {
    Map<String, Object> value(ConfigService configService);

    Map<String, Object> value(String id);
}
