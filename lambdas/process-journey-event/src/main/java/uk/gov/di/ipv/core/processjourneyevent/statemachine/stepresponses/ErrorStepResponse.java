package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ErrorStepResponse implements StepResponse {
    private static final String ERROR = "error";
    private String pageId;
    private String statusCode;
    @Getter private Boolean mitigationStart;

    public Map<String, Object> value() {
        return Map.of("type", ERROR, "page", pageId, "statusCode", Integer.parseInt(statusCode));
    }
}
