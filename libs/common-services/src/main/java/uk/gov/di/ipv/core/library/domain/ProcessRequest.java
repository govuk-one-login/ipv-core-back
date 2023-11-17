package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Data
public class ProcessRequest extends JourneyRequest {
    private String scoreType;
    private Integer scoreThreshold;
    private Boolean isUserInitiated;

    @Builder(builderMethodName = "processRequestBuilder")
    public ProcessRequest(
            String ipvSessionId,
            String ipAddress,
            String clientOAuthSessionId,
            String journey,
            String featureSet,
            String scoreType,
            Integer scoreThreshold,
            Boolean isUserInitiated) {
        super(ipvSessionId, ipAddress, clientOAuthSessionId, journey, featureSet);
        this.scoreType = scoreType;
        this.scoreThreshold = scoreThreshold;
        this.isUserInitiated = isUserInitiated;
    }
}
