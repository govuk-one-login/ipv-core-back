package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@EqualsAndHashCode(callSuper = true)
@AllArgsConstructor
@NoArgsConstructor
@Data
@SuperBuilder
public class CriJourneyRequest extends JourneyRequest {
    private String language;

    public CriJourneyRequest(
            String ipvSessionId,
            String ipAddress,
            String deviceInformation,
            String clientOAuthSessionId,
            String journey,
            String featureSet,
            String language) {
        super(
                ipvSessionId,
                ipAddress,
                deviceInformation,
                clientOAuthSessionId,
                journey,
                featureSet);
        this.language = language;
    }
}
