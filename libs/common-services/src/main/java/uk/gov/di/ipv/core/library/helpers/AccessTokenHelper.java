package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;

import java.time.Instant;

public class AccessTokenHelper {
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    public static AccessToken parseAccessToken(APIGatewayProxyRequestEvent input)
            throws ParseException {
        return AccessToken.parse(
                RequestHelper.getHeaderByKey(input.getHeaders(), AUTHORIZATION_HEADER_KEY),
                AccessTokenType.BEARER);
    }

    public static APIGatewayProxyResponseEvent validateAccessTokenMetadata(
            AccessTokenMetadata accessTokenMetadata) {
        if (StringUtils.isNotBlank(accessTokenMetadata.getRevokedAtDateTime())) {
            return ApiGatewayResponseGenerator.getRevokedAccessTokenApiGatewayProxyResponseEvent(
                    accessTokenMetadata);
        }

        if (accessTokenHasExpired(accessTokenMetadata)) {
            return ApiGatewayResponseGenerator.getExpiredAccessTokenApiGatewayProxyResponseEvent(
                    accessTokenMetadata);
        }
        return null;
    }

    private static boolean accessTokenHasExpired(AccessTokenMetadata accessTokenMetadata) {
        if (StringUtils.isNotBlank(accessTokenMetadata.getExpiryDateTime())) {
            return Instant.now().isAfter(Instant.parse(accessTokenMetadata.getExpiryDateTime()));
        }
        return false;
    }
}
