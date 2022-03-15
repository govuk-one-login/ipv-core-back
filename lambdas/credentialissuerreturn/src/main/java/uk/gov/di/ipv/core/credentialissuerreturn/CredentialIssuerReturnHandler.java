package uk.gov.di.ipv.core.credentialissuerreturn;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.KmsSigner;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;

import java.util.Optional;

public class CredentialIssuerReturnHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String NEXT_JOURNEY_STEP_URI = "/journey/next";

    private final CredentialIssuerService credentialIssuerService;
    private final ConfigurationService configurationService;

    public CredentialIssuerReturnHandler(
            CredentialIssuerService credentialIssuerService,
            ConfigurationService configurationService) {
        this.credentialIssuerService = credentialIssuerService;
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerReturnHandler() {
        this.configurationService = new ConfigurationService();
        JWSSigner signer = new KmsSigner(configurationService.getSharedAttributesSigningKeyId());

        this.credentialIssuerService = new CredentialIssuerService(configurationService, signer);
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

        try {
            BearerAccessToken accessToken =
                    credentialIssuerService.exchangeCodeForToken(request, credentialIssuerConfig);
            String verifiableCredential =
                    credentialIssuerService.getVerifiableCredential(
                            accessToken, credentialIssuerConfig, request.getIpvSessionId());
            credentialIssuerService.persistUserCredentials(verifiableCredential, request);

            JourneyResponse journeyResponse = new JourneyResponse(NEXT_JOURNEY_STEP_URI);
            return ApiGatewayResponseGenerator.proxyJsonResponse(200, journeyResponse);
        } catch (CredentialIssuerException e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getHttpStatusCode(), e.getErrorResponse());
        }
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
