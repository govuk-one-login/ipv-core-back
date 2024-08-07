package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.net.URI;
import java.net.URISyntaxException;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_BAD_REQUEST;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class JourneyRequest {
    private String ipvSessionId;
    private String ipAddress;
    private String deviceInformation;
    private String clientOAuthSessionId;
    private String journey;
    private String featureSet;
    private String language;

    public JourneyRequest(
            String ipvSessionId,
            String ipAddress,
            String deviceInformation,
            String clientOAuthSessionId,
            String journey,
            String featureSet) {
        this.ipvSessionId = ipvSessionId;
        this.ipAddress = ipAddress;
        this.deviceInformation = deviceInformation;
        this.clientOAuthSessionId = clientOAuthSessionId;
        this.journey = journey;
        this.featureSet = featureSet;
    }

    public URI getJourneyUri() throws HttpResponseExceptionWithErrorBody {
        if (journey == null) {
            throw new HttpResponseExceptionWithErrorBody(
                    SC_BAD_REQUEST, ErrorResponse.MISSING_JOURNEY_EVENT);
        }
        try {
            return new URI(journey);
        } catch (URISyntaxException e) {
            throw new HttpResponseExceptionWithErrorBody(
                    SC_BAD_REQUEST, ErrorResponse.INVALID_JOURNEY_EVENT);
        }
    }
}
