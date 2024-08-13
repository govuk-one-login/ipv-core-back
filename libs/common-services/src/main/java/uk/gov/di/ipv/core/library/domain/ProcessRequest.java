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
            String language,
            Map<String, Object> lambdaInput) {
        super(
                ipvSessionId,
                ipAddress,
                deviceInformation,
                clientOAuthSessionId,
                journey,
                featureSet,
                language);
        this.lambdaInput = lambdaInput;
    }
}
