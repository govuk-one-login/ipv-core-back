package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.helpers.RequestHelper;
import uk.gov.di.ipv.service.CredentialIssuerService;

import java.net.URI;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

public class CredentialIssuerHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerHandler.class);

    private final CredentialIssuerService credentialIssuerService;

    private Set<CredentialIssuerConfig> credentialIssuers;

    public CredentialIssuerHandler(CredentialIssuerService credentialIssuerService, Set<CredentialIssuerConfig> credentialIssuerConfig) {
        this.credentialIssuerService = credentialIssuerService;
        this.credentialIssuers = credentialIssuerConfig;
    }

    public CredentialIssuerHandler() {
        CredentialIssuerConfig passportIssuer = new CredentialIssuerConfig("PassportIssuer", URI.create("http://www.example.com"));
        CredentialIssuerConfig fraudIssuer = new CredentialIssuerConfig("FraudIssuer", URI.create("http://www.example.com"));
        this.credentialIssuers = Set.of(passportIssuer, fraudIssuer);
        this.credentialIssuerService = new CredentialIssuerService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        CredentialIssuerRequestDto request = RequestHelper.convertRequest(input, CredentialIssuerRequestDto.class);

        var errorResponse = validate(request);
        if (errorResponse.isPresent()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
        }

        CredentialIssuerConfig credentialIssuerConfig = getCredentialIssuerConfig(request).get();

        try {
            AccessToken accessToken = credentialIssuerService.exchangeCodeForToken(request, credentialIssuerConfig);
            // todo var credential = getCredential(accessToken);
            // todo save credential
            return ApiGatewayResponseGenerator.proxyJsonResponse(200, Collections.EMPTY_MAP);
        } catch (CredentialIssuerException e) {
            LOGGER.error("Could not exchange authorization code for token: {}", e.getMessage(), e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.InvalidTokenRequest);
        }

    }

    private Optional<ErrorResponse> validate(CredentialIssuerRequestDto request) {
        if (StringUtils.isBlank(request.getAuthorization_code())) {
            return Optional.of(ErrorResponse.MissingAuthorizationCode);
        }

        if (StringUtils.isBlank(request.getCredential_issuer_id())) {
            return Optional.of(ErrorResponse.MissingCredentialIssuerId);
        }

        if (StringUtils.isBlank(request.getIpv_session_id())) {
            return Optional.of(ErrorResponse.MissingSessionId);
        }

        if (getCredentialIssuerConfig(request).isEmpty()) {
            return Optional.of(ErrorResponse.InvalidCredentialIssuerId);
        }
        return Optional.empty();
    }

    private Optional<CredentialIssuerConfig> getCredentialIssuerConfig(CredentialIssuerRequestDto request) {
        return credentialIssuers.stream()
                .filter(config -> request.getCredential_issuer_id().equals(config.getId()))
                .findFirst();
    }

}
