package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.util.Map;

@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Data
public class ProcessRequest extends JourneyRequest {
    private Map<String, Object> lambdaInput;

    @Builder(builderMethodName = "processRequestBuilder")
    public ProcessRequest(
            String ipvSessionId,
            String ipAddress,
            String deviceInformation,
            String clientOAuthSessionId,
            String journey,
            String featureSet,
            Map<String, Object> lambdaInput,
            String traceParent,
            String traceState,
            String dynatrace) {
        super(
                ipvSessionId,
                ipAddress,
                deviceInformation,
                clientOAuthSessionId,
                journey,
                featureSet,
                traceParent,
                traceState,
                dynatrace);
        this.lambdaInput = lambdaInput;
    }
}
