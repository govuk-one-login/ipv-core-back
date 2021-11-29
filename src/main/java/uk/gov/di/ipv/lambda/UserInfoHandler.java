package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.UserInfoDto;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.helpers.RequestHelper;
import uk.gov.di.ipv.service.UserInfoService;

public class UserInfoHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoHandler.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";

    private UserInfoService userInfoService;

    public UserInfoHandler(UserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }

    public UserInfoHandler() {
        this.userInfoService = new UserInfoService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        var accessTokenString = RequestHelper.getHeader(input.getHeaders(), AUTHORIZATION_HEADER);
        if (accessTokenString.isEmpty()) {
            LOGGER.error("Missing access token from Authorization header");
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.MissingAccessToken);
        }

        try {
            AccessToken accessToken = AccessToken.parse(accessTokenString.get());
            UserInfoDto userInfo = userInfoService.handleUserInfo(accessToken);

            return ApiGatewayResponseGenerator.proxyJsonResponse(200, userInfo);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.FailedToParseAccessToken);
        }
    }
}
