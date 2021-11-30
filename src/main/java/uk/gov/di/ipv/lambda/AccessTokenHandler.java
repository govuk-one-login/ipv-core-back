package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.TokenRequestDto;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.helpers.RequestHelper;
import uk.gov.di.ipv.service.AccessTokenService;

public class AccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenHandler.class);

    private final AccessTokenService accessTokenService;

    public AccessTokenHandler(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }

    public AccessTokenHandler() {
        this.accessTokenService = new AccessTokenService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        try {
            TokenRequestDto tokenRequestDto = RequestHelper.convertRequest(input, TokenRequestDto.class);

            if (tokenRequestDto.getCode().isEmpty()) {
                LOGGER.error("Missing authorisation code from the token request");
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.MissingAuthorizationCode);
            }

            TokenRequest tokenRequest = new TokenRequest(
                    null,
                    new ClientID(tokenRequestDto.getClient_id()),
                    new AuthorizationCodeGrant(
                            new AuthorizationCode(tokenRequestDto.getCode()),
                            tokenRequestDto.getRedirect_uri())
            );

            TokenResponse tokenResponse = accessTokenService.exchangeCodeForToken(tokenRequest);

            if (tokenResponse instanceof TokenErrorResponse) {
                TokenErrorResponse tokenErrorResponse = tokenResponse.toErrorResponse();
                LOGGER.error(tokenErrorResponse.getErrorObject().getDescription());
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.FailedToExchangeAuthorizationCode);
            }

            AccessTokenResponse accessTokenResponse = tokenResponse.toSuccessResponse();

            return ApiGatewayResponseGenerator.proxyJsonResponse(200, accessTokenResponse.toJSONObject());
        } catch (IllegalArgumentException e) {
            LOGGER.error("Token request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.FailedToParseTokenRequest);
        }
    }
}
