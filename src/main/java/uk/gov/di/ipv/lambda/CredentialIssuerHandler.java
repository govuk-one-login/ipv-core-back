package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.helpers.RequestHelper;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class CredentialIssuerHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private Set<String> validCredentialIssuers = Set.of("PassportIssuer", "FraudIssuer");

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        Map<String, String> body = RequestHelper.parseRequestBody(input.getBody());
        ObjectMapper objectMapper = new ObjectMapper();
        CredentialIssuerRequestDto request = objectMapper.convertValue(body, CredentialIssuerRequestDto.class);

        var errorResponse = validate(request);
        if (errorResponse.isPresent()) {
            return errorResponse.get();
        } else {
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

}
