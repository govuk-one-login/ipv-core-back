package uk.gov.di.ipv.core.accesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.AccessTokenService;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.net.URI;

public class AccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenHandler.class);

    private final AccessTokenService accessTokenService;
    private final AuthorizationCodeService authorizationCodeService;

    static {
        // Set the default synchronous HTTP client to UrlConnectionHttpClient
        System.setProperty(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    public AccessTokenHandler(
            AccessTokenService accessTokenService,
            AuthorizationCodeService authorizationCodeService) {
        this.accessTokenService = accessTokenService;
        this.authorizationCodeService = authorizationCodeService;
    }

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenHandler() {
        this.accessTokenService = new AccessTokenService();
        this.authorizationCodeService = new AuthorizationCodeService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            TokenRequest tokenRequest = createTokenRequest(input.getBody());

            ValidationResult<ErrorObject> validationResult =
                    accessTokenService.validateTokenRequest(tokenRequest);
            if (!validationResult.isValid()) {
                LOGGER.error(
                        "Invalid access token request, error description: {}",
                        validationResult.getError().getDescription());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        getHttpStatusCodeForErrorResponse(validationResult.getError()),
                        validationResult.getError().toJSONObject());
            }

            String authorizationCodeFromRequest =
                    ((AuthorizationCodeGrant) tokenRequest.getAuthorizationGrant())
                            .getAuthorizationCode()
                            .getValue();
            String ipvSessionId =
                    authorizationCodeService.getIpvSessionIdByAuthorizationCode(
                            authorizationCodeFromRequest);

            if (StringUtils.isBlank(ipvSessionId)) {
                LOGGER.error(
                        "Access Token could not be issued. The supplied authorization code was not found in the database.");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_GRANT.getHTTPStatusCode(),
                        OAuth2Error.INVALID_GRANT.toJSONObject());
            }

            TokenResponse tokenResponse = accessTokenService.generateAccessToken(tokenRequest);
            AccessTokenResponse accessTokenResponse = tokenResponse.toSuccessResponse();

            accessTokenService.persistAccessToken(accessTokenResponse, ipvSessionId);

            authorizationCodeService.revokeAuthorizationCode(authorizationCodeFromRequest);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, accessTokenResponse.toJSONObject());
        } catch (ParseException e) {
            LOGGER.error(
                    "Token request could not be parsed: " + e.getErrorObject().getDescription(), e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    getHttpStatusCodeForErrorResponse(e.getErrorObject()),
                    e.getErrorObject().toJSONObject());
        }
    }

    private TokenRequest createTokenRequest(String requestBody) throws ParseException {
        // The URI is not needed/consumed in the resultant TokenRequest
        // therefore any value can be passed here to ensure the parse method
        // successfully materialises a TokenRequest
        URI arbitraryUri = URI.create("https://gds");
        HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, arbitraryUri);
        request.setQuery(requestBody);
        request.setContentType(ContentType.APPLICATION_URLENCODED.getType());
        return TokenRequest.parse(request);
    }

    private int getHttpStatusCodeForErrorResponse(ErrorObject errorObject) {
        return errorObject.getHTTPStatusCode() > 0
                ? errorObject.getHTTPStatusCode()
                : HttpStatus.SC_BAD_REQUEST;
    }
}
