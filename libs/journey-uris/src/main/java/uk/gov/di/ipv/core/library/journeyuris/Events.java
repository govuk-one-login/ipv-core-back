package uk.gov.di.ipv.core.library.journeyuris;

public class Events {
    private Events() {
        throw new IllegalStateException("String constants class");
    }

    // This event is a special value that is caught explicitly by the journey event handler
    public static final String BUILD_CLIENT_OAUTH_RESPONSE_EVENT = "build-client-oauth-response";
}
