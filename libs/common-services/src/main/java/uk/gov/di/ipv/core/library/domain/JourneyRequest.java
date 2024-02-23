package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class JourneyRequest {
    private String ipvSessionId;
    private String ipAddress;
    private String clientOAuthSessionId;
    private String journey;
    private String featureSet;

    public List<String> getFeatureSet() {
        return (featureSet != null) ? Arrays.asList(featureSet.split(",")) : null;
    }
}
