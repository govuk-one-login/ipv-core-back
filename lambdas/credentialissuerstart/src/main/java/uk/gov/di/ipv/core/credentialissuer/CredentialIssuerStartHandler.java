package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.credentialissuer.domain.CriDetails;
import uk.gov.di.ipv.core.credentialissuer.domain.CriResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;
import java.util.Optional;

public class CredentialIssuerStartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public static final String CRI_ID = "criId";

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

        Map<String, String> pathParameters = input.getPathParameters();

        var errorResponse = validate(pathParameters);
        if (errorResponse.isPresent()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
        }

        CredentialIssuerConfig credentialIssuerConfig =
                getCredentialIssuerConfig(pathParameters.get(CRI_ID));

        if (credentialIssuerConfig == null) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    400, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }

        CriResponse criResponse =
                new CriResponse(
                        new CriDetails(
                                credentialIssuerConfig.getId(),
                                credentialIssuerConfig.getIpvClientId(),
                                credentialIssuerConfig.getAuthorizeUrl().toString()));

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, criResponse);
    }

    @Tracing
    private Optional<ErrorResponse> validate(Map<String, String> pathParameters) {
        if (pathParameters == null || StringUtils.isBlank(pathParameters.get(CRI_ID))) {
            return Optional.of(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        return Optional.empty();
    }

    private CredentialIssuerConfig getCredentialIssuerConfig(String criId) {
        return configurationService.getCredentialIssuer(criId);
    }
}
