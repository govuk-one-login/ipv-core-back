package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Data
public class CriJourneyRequest extends JourneyRequest {
    private String language;

    @Builder(builderMethodName = "criJourneyRequestBuilder")
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
