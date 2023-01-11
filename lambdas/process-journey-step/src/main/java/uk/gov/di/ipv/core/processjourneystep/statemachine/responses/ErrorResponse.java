package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse implements JourneyStepResponse {

    private static final String ERROR = "error";
    private String pageId;
    private String statusCode;

    public Map<String, Object> value(ConfigurationService configurationService) {
        return value(pageId);
    }

    public Map<String, Object> value(String id) {
        return Map.of("type", ERROR, "page", id, "statusCode", Integer.parseInt(statusCode));
    }
}
