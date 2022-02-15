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
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.core.library.service.AccessTokenService;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.net.URI;
import java.util.NoSuchElementException;
import java.util.Objects;

public class AccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenHandler.class);

    private final AccessTokenService accessTokenService;
    private final AuthorizationCodeService authorizationCodeService;
    private final ConfigurationService configurationService;
    private final TokenRequestValidator tokenRequestValidator;

    public AccessTokenHandler(
            AccessTokenService accessTokenService,
            AuthorizationCodeService authorizationCodeService,
            ConfigurationService configurationService,
            TokenRequestValidator tokenRequestValidator) {
        this.accessTokenService = accessTokenService;
        this.authorizationCodeService = authorizationCodeService;
        this.configurationService = configurationService;
        this.tokenRequestValidator = tokenRequestValidator;
    }

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenHandler() {
        this.configurationService = new ConfigurationService();
        this.accessTokenService = new AccessTokenService(configurationService);
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.tokenRequestValidator = new TokenRequestValidator();
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

            ValidationResult<ErrorObject> extractJwt =
                    tokenRequestValidator.validateExtractedJwt(input.getBody());
            if (!extractJwt.isValid()) {
                LOGGER.error("Unable to  extract JWT string ");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        getHttpStatusCodeForErrorResponse(extractJwt.getError()),
                        extractJwt.getError().toJSONObject());
            }

            AuthorizationCodeGrant authorizationGrant =
                    (AuthorizationCodeGrant) tokenRequest.getAuthorizationGrant();

            AuthorizationCodeItem authorizationCodeItem =
                    authorizationCodeService
                            .getAuthorizationCodeItem(
                                    authorizationGrant.getAuthorizationCode().getValue())
                            .orElseThrow();

            if (redirectUrlsDoNotMatch(authorizationCodeItem, authorizationGrant)) {
                LOGGER.error(
                        "Redirect URL in token request does not match that received in auth code request. Session ID: {}",
                        authorizationCodeItem.getIpvSessionId());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_REQUEST.getHTTPStatusCode(),
                        OAuth2Error.INVALID_REQUEST.toJSONObject());
            }

            AccessTokenResponse accessTokenResponse =
                    accessTokenService.generateAccessToken(tokenRequest).toSuccessResponse();

            accessTokenService.persistAccessToken(
                    accessTokenResponse, authorizationCodeItem.getIpvSessionId());

            authorizationCodeService.revokeAuthorizationCode(authorizationCodeItem.getAuthCode());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, accessTokenResponse.toJSONObject());
        } catch (ParseException e) {
            LOGGER.error(
                    "Token request could not be parsed: " + e.getErrorObject().getDescription(), e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    getHttpStatusCodeForErrorResponse(e.getErrorObject()),
                    e.getErrorObject().toJSONObject());
        } catch (NoSuchElementException e) {
            LOGGER.error(
                    "Access Token could not be issued. The supplied authorization code was not found in the database.");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.INVALID_GRANT.getHTTPStatusCode(),
                    OAuth2Error.INVALID_GRANT.toJSONObject());
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

    private boolean redirectUrlsDoNotMatch(
            AuthorizationCodeItem authorizationCodeItem,
            AuthorizationCodeGrant authorizationGrant) {

        if (Objects.isNull(authorizationCodeItem.getRedirectUrl())
                && Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return false;
        }

        if (Objects.isNull(authorizationCodeItem.getRedirectUrl())
                || Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return true;
        }

        return !authorizationGrant
                .getRedirectionURI()
                .toString()
                .equals(authorizationCodeItem.getRedirectUrl());
    }
}
