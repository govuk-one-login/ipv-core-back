package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.helpers.RequestBodyHelper;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class CredentialIssuerHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private Set<String> validCredentialIssuers = Set.of("PassportIssuer", "FraudIssuer");

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        Map<String, String> body = RequestBodyHelper.parseRequestBody(input.getBody());
        String authorizationCode = body.get("authorization_code");
        String credentialIssuer = body.get("credential_issuer_id");

        if (StringUtils.isBlank(authorizationCode)) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.MissingAuthorizationCode);
        }

        if (StringUtils.isBlank(credentialIssuer) || !validCredentialIssuers.contains(credentialIssuer)) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.MissingCredentialIssuerId);
        }

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, Collections.EMPTY_MAP);

    }

}
