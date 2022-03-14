package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.credentialissuer.domain.CriResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Optional;

public class CredentialIssuerStartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final ConfigurationService configurationService;

    public CredentialIssuerStartHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerStartHandler() {
        this.configurationService = new ConfigurationService();
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        CredentialIssuerRequestDto request =
                RequestHelper.convertRequest(input, CredentialIssuerRequestDto.class);

        var errorResponse = validate(request);
        if (errorResponse.isPresent()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
        }

        CredentialIssuerConfig credentialIssuerConfig = getCredentialIssuerConfig(request);

        CriResponse criResponse =
                new CriResponse(
                        credentialIssuerConfig.getId(),
                        credentialIssuerConfig.getAuthorizeUrl().toString(),
                        request.getRedirectUri());

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, criResponse);
    }

    @Tracing
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
        return configurationService.getCredentialIssuer(request.getCredentialIssuerId());
    }
}
