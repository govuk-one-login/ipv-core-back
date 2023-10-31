package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class JourneyRequest {
    private String ipvSessionId;
    private String ipAddress;
    private String clientOAuthSessionId;
    private String journey;
    @Builder.Default
    private String context = "";
    private String featureSet;
}
