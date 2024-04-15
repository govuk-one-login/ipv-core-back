package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.http.HttpStatus;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.net.URI;
import java.net.URISyntaxException;

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

    public URI getJourneyUri() throws HttpResponseExceptionWithErrorBody {
        if (journey == null) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_JOURNEY_EVENT);
        }
        try {
            return new URI(journey);
        } catch (URISyntaxException e) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_JOURNEY_EVENT);
        }
    }
}
