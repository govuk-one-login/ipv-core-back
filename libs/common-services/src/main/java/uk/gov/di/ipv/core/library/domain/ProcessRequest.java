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
            String clientOAuthSessionId,
            String journey,
            String featureSet,
            Map<String, Object> lambdaInput) {
        super(ipvSessionId, ipAddress, clientOAuthSessionId, journey, featureSet);
        this.lambdaInput = lambdaInput;
    }
}
