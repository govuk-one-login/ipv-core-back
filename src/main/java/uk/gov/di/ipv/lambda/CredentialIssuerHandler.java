package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.minidev.json.JSONObject;
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

public class CredentialIssuerHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerHandler.class);

    private final CredentialIssuerService credentialIssuerService;

    protected static final CredentialIssuerConfig PASSPORT_ISSUER =
            new CredentialIssuerConfig(
                    "PassportIssuer",
                    URI.create("http://www.example.com"),
                    URI.create("http://www.example.com/credential"));
    protected static final CredentialIssuerConfig FRAUD_ISSUER =
            new CredentialIssuerConfig(
                    "FraudIssuer",
                    URI.create("http://www.example.com"),
                    URI.create("http://www.example.com/credential"));
    protected static final Set<CredentialIssuerConfig> CREDENTIAL_ISSUERS =
            Set.of(PASSPORT_ISSUER, FRAUD_ISSUER);

    public CredentialIssuerHandler(CredentialIssuerService credentialIssuerService) {
        this.credentialIssuerService = credentialIssuerService;
    }

    public CredentialIssuerHandler() {
        this.credentialIssuerService = new CredentialIssuerService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        CredentialIssuerRequestDto request =
                RequestHelper.convertRequest(input, CredentialIssuerRequestDto.class);

        var errorResponse = validate(request);
        if (errorResponse.isPresent()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
        }
        CredentialIssuerConfig credentialIssuerConfig = getCredentialIssuerConfig(request);

        BearerAccessToken accessToken;
        try {
            accessToken =
                    credentialIssuerService.exchangeCodeForToken(request, credentialIssuerConfig);
        } catch (CredentialIssuerException e) {
            LOGGER.error("Could not exchange authorization code for token: {}", e.getMessage(), e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    400, ErrorResponse.INVALID_TOKEN_REQUEST);
        }

        try {
            JSONObject credential =
                    credentialIssuerService.getCredential(accessToken, credentialIssuerConfig);
            // todo save credential
        } catch (CredentialIssuerException e) {
            LOGGER.error(
                    "Could not retrieve protected resource from credential issuer: {}",
                    e.getMessage(),
                    e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    500, ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
        }

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, Collections.EMPTY_MAP);
    }

    private Optional<ErrorResponse> validate(CredentialIssuerRequestDto request) {
        if (StringUtils.isBlank(request.getAuthorizationCode())) {
            return Optional.of(ErrorResponse.MISSING_AUTHORIZATION_CODE);
        }

        if (StringUtils.isBlank(request.getCredentialIssuerId())) {
            return Optional.of(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }

        if (StringUtils.isBlank(request.getIpvSessionId())) {
            return Optional.of(ErrorResponse.MISSING_IPV_SESSION_ID);
        }

        if (getCredentialIssuerConfig(request) == null) {
            return Optional.of(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }
        return Optional.empty();
    }

    private CredentialIssuerConfig getCredentialIssuerConfig(CredentialIssuerRequestDto request) {
        return CREDENTIAL_ISSUERS.stream()
                .filter(config -> request.getCredentialIssuerId().equals(config.getId()))
                .findFirst()
                .orElse(null);
    }
}
