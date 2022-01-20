package uk.gov.di.ipv.core.issuedcredentials;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.util.Collections;
import java.util.Map;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;

public class IssuedCredentialsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = Logger.getLogger(IssuedCredentialsHandler.class.getName());
    private static final Integer OK = 200;
    private static final Integer BAD_REQUEST = 400;

    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";

    private final UserIdentityService userIdentityService;

    static {
        // Set the default synchronous HTTP client to UrlConnectionHttpClient
        System.setProperty(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    public IssuedCredentialsHandler(UserIdentityService userIdentityService) {
        this.userIdentityService = userIdentityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public IssuedCredentialsHandler() {
        this.userIdentityService = new UserIdentityService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        var ipvSessionId =
                RequestHelper.getHeaderByKey(input.getHeaders(), IPV_SESSION_ID_HEADER_KEY);

        if (ipvSessionId == null || ipvSessionId.isEmpty()) {
            LOGGER.log(WARNING, "User credentials could not be retrieved. No session ID received.");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, Collections.emptyMap());
        }

        Map<String, String> credentials =
                userIdentityService.getUserIssuedCredentials(ipvSessionId);

        // This is here to allow us to test the functionality with core-front in the short term.
        // When ready, we can switch to returning the credentials retrieved above.
        Map<String, String> stubCredentials = getStubCredentials();

        return ApiGatewayResponseGenerator.proxyJsonResponse(OK, stubCredentials);
    }

    public static Map<String, String> getStubCredentials() {
        return Map.of(
                "passportIssuer",
                        "{\"attributes\":{\"names\":{\"givenNames\":[\"Mary\"],\"familyName\":\"Watson\"},\"passportNo\":\"824159121\",\"passportExpiryDate\":\"2030-01-01\",\"dateOfBirth\":\"2021-03-01\"},\"gpg45Score\":{\"evidence\":{\"strength\":5,\"validity\":3}}}",
                "fraudIssuer",
                        "{\"attributes\":{\"names\":{\"givenNames\":[\"Mary\"],\"familyName\":\"Watson\"},\"someFraudAttribute\":\"notsurewhatthatmightbe\"},\"gpg45Score\":{\"fraud\":0}}",
                "addressIssuer",
                        "{\"attributes\":{\"address\":{\"postcode\":\"SW1A1AA\",\"houseNumber\":10}}}");
    }
}
