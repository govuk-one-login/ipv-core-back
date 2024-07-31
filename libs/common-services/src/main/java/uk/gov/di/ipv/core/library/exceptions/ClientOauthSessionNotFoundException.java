package uk.gov.di.ipv.core.library.exceptions;

import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class ClientOauthSessionNotFoundException extends HttpResponseExceptionWithErrorBody {
    public ClientOauthSessionNotFoundException() {
        // Client OAuth sessions are read using an ID from the IPV Session and
        // have a longer expiry time, so this is an internal server error
        super(HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.CLIENT_OAUTH_SESSION_NOT_FOUND);
    }
}
