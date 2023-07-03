package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageResponse implements JourneyStepResponse {

    private String pageId;

    public Map<String, Object> value(ConfigService configService) {
        return value(pageId);
    }

    public Map<String, Object> value(String id) {
        return Map.of("page", id);
    }
}
