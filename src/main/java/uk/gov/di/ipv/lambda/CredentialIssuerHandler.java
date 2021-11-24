package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.helpers.RequestHelper;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class CredentialIssuerHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerHandler.class);

    private Set<String> validCredentialIssuers = Set.of("PassportIssuer", "FraudIssuer");


    private Map<String, CredentialIssuerConfig> validCredentialIssuers2 = Map.of(
            "PassportIssuer", new CredentialIssuerConfig("PassportIssuer", URI.create("http://www.example.com"))
    );

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        Map<String, String> body = RequestHelper.parseRequestBody(input.getBody());
        ObjectMapper objectMapper = new ObjectMapper();
        CredentialIssuerRequestDto request = objectMapper.convertValue(body, CredentialIssuerRequestDto.class);

        var errorResponse = validate(request);
        if (errorResponse.isPresent()) {
            return errorResponse.get();
        } else {

            CredentialIssuerConfig credentialIssuerConfig = validCredentialIssuers2.get(request.getCredential_issuer_id());

            AuthorizationCode authorizationCode = new AuthorizationCode(request.getAuthorization_code());
            TokenRequest tokenRequest = new TokenRequest(
                    credentialIssuerConfig.getTokenUrl(),
                    new ClientID("IPV_CLIENT_1"),
                    new AuthorizationCodeGrant(authorizationCode, credentialIssuerConfig.getTokenUrl())
            );

            HTTPResponse httpResponse = sendHttpRequest(tokenRequest.toHTTPRequest());

            return ApiGatewayResponseGenerator.proxyJsonResponse(200, Collections.EMPTY_MAP);
        }

    }

    private Optional<APIGatewayProxyResponseEvent> validate(CredentialIssuerRequestDto request) {
        if (StringUtils.isBlank(request.getAuthorization_code())) {
            return Optional.of(ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.MissingAuthorizationCode));
        }

        if (StringUtils.isBlank(request.getCredential_issuer_id())) {
            return Optional.of(ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.MissingCredentialIssuerId));
        }

        if (!validCredentialIssuers.contains(request.getCredential_issuer_id())) {
            return Optional.of(ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.InvalidCredentialIssuerId));
        }
        return Optional.empty();
    }

    private HTTPResponse sendHttpRequest(HTTPRequest httpRequest) {
        try {
            return httpRequest.send();
        } catch (IOException | SerializeException exception) {
            LOGGER.error("Failed to send a http request", exception);
            // todo what error to throw, and how to handle
            throw new RuntimeException("Failed to send a http request", exception);
        }
    }

}
