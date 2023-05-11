package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class JourneyRequest {
    private String ipvSessionId;
    private String ipAddress;
    private String clientOAuthSessionId;
    private String featureSet;
}
