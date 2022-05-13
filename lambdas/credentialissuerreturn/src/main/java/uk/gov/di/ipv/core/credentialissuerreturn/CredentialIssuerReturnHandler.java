package uk.gov.di.ipv.core.credentialissuerreturn;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.KmsEs256Signer;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;

import java.util.Optional;

public class CredentialIssuerReturnHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER =
            LoggerFactory.getLogger(CredentialIssuerReturnHandler.class);
    private static final String NEXT_JOURNEY_STEP_URI = "/journey/next";

    private final CredentialIssuerService credentialIssuerService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;

    public CredentialIssuerReturnHandler(
            CredentialIssuerService credentialIssuerService,
            ConfigurationService configurationService,
            AuditService auditService) {
        this.credentialIssuerService = credentialIssuerService;
        this.configurationService = configurationService;
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerReturnHandler() {
        this.configurationService = new ConfigurationService();
        JWSSigner signer = new KmsEs256Signer(configurationService.getSigningKeyId());

        this.credentialIssuerService = new CredentialIssuerService(configurationService, signer);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        CredentialIssuerRequestDto request =
                RequestHelper.convertRequest(input, CredentialIssuerRequestDto.class);
        try {

            auditService.sendAuditEvent(AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED);

            var errorResponse = validate(request);
            if (errorResponse.isPresent()) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
            }
            CredentialIssuerConfig credentialIssuerConfig = getCredentialIssuerConfig(request);

            BearerAccessToken accessToken =
                    credentialIssuerService.exchangeCodeForToken(request, credentialIssuerConfig);
            String verifiableCredential =
                    credentialIssuerService.getVerifiableCredential(
                            accessToken, credentialIssuerConfig, request.getIpvSessionId());

            auditService.sendAuditEvent(
                    AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED);

            credentialIssuerService.persistUserCredentials(verifiableCredential, request);

            JourneyResponse journeyResponse = new JourneyResponse(NEXT_JOURNEY_STEP_URI);
            return ApiGatewayResponseGenerator.proxyJsonResponse(200, journeyResponse);
        } catch (CredentialIssuerException e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getHttpStatusCode(), e.getErrorResponse());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
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
