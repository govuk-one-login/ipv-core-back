package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.helpers.RequestHelper;
import uk.gov.di.ipv.service.AccessTokenService;
import uk.gov.di.ipv.service.UserIdentityService;
import uk.gov.di.ipv.validation.ValidationResult;

import java.util.Map;

public class UserIdentityHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserIdentityHandler.class);
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    private final UserIdentityService userIdentityService;
    private final AccessTokenService accessTokenService;

    public UserIdentityHandler(UserIdentityService userIdentityService, AccessTokenService accessTokenService) {
        this.userIdentityService = userIdentityService;
        this.accessTokenService = accessTokenService;
    }

    public UserIdentityHandler() {
        this.userIdentityService = new UserIdentityService();
        this.accessTokenService = new AccessTokenService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        ValidationResult<ErrorObject> validationResult = validateRequest(input.getHeaders());

        if (!validationResult.isValid()) {
            LOGGER.error(validationResult.getError().getDescription());
            return ApiGatewayResponseGenerator.proxyJsonResponse(validationResult.getError().getHTTPStatusCode(), validationResult.getError().toJSONObject());
        }

        try {
            String accessTokenString = RequestHelper.getHeaderByKey(input.getHeaders(), AUTHORIZATION_HEADER_KEY);

            AccessToken.parse(accessTokenString);

            String ipvSessionId = accessTokenService.getIpvSessionIdByAccessToken(accessTokenString);

            if (StringUtils.isBlank(ipvSessionId)) {
                LOGGER.error("User credential could not be retrieved. The supplied access token was not found in the database.");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(), OAuth2Error.ACCESS_DENIED.appendDescription(" - The supplied access token was not found in the database").toJSONObject());
            }

            Map<String, String> credentials = userIdentityService.getUserIssuedCredentials(ipvSessionId);

            return ApiGatewayResponseGenerator.proxyJsonResponse(200, credentials);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, OAuth2Error.INVALID_GRANT.appendDescription(" - Failed to parse access token").toJSONObject());
        }
    }

    private ValidationResult<ErrorObject> validateRequest(Map<String, String> requestHeaders) {
        if (StringUtils.isBlank(RequestHelper.getHeaderByKey(requestHeaders, AUTHORIZATION_HEADER_KEY))) {
            return new ValidationResult<>(false, OAuth2Error.INVALID_REQUEST.appendDescription(" - Authorization header is missing from token request"));
        }

        return ValidationResult.createValidResult();
    }
}
