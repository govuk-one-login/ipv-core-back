package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.net.URI;
import java.net.URISyntaxException;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_BAD_REQUEST;

@AllArgsConstructor
@NoArgsConstructor
@Data
@SuperBuilder
public class JourneyRequest {
    private String ipvSessionId;
    private String ipAddress;
    private String deviceInformation;
    private String clientOAuthSessionId;
    private String journey;
    private String featureSet;

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
