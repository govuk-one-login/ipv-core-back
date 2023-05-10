package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class JourneyRequest {
    private String ipvSessionId;
    private String ipAddress;
}
