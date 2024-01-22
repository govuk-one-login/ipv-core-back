package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;

import java.util.Map;

@Getter
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JourneyStepResponse implements StepResponse {
    private IpvJourneyTypes journeyType;
    private String initialState;
    private Boolean mitigationStart;

    public Map<String, Object> value() {
        throw new IllegalStateException("Journey step responses should be processed internally");
    }
}
