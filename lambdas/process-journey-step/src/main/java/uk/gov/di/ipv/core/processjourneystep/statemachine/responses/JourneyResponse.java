package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JourneyResponse implements JourneyStepResponse {

    private String journeyStepId;

    public Map<String, Object> value(ConfigService configService) {
        return value(journeyStepId);
    }

    public Map<String, Object> value(String id) {
        return Map.of("journey", id);
    }
}
