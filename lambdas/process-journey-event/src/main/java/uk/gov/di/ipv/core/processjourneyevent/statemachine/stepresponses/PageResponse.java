package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageResponse implements JourneyStepResponse {

    private String pageId;

    public Map<String, Object> value() {
        return Map.of("page", pageId);
    }
}
