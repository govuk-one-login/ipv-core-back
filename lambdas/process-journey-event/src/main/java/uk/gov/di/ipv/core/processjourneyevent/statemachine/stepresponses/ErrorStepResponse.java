package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ErrorStepResponse implements JourneyStepResponse {

    private static final String ERROR = "error";
    private String pageId;
    private String statusCode;

    public Map<String, Object> value() {
        return Map.of("type", ERROR, "page", pageId, "statusCode", Integer.parseInt(statusCode));
    }
}
