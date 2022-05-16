package uk.gov.di.ipv.core.credentialissuerreturn;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
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
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.util.Optional;

public class CredentialIssuerReturnHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER =
            LoggerFactory.getLogger(CredentialIssuerReturnHandler.class);
    private static final String NEXT_JOURNEY_STEP_URI = "/journey/next";

    private final CredentialIssuerService credentialIssuerService;
    private final ConfigurationService configurationService;
    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final IpvSessionService ipvSessionService;

    public CredentialIssuerReturnHandler(
            CredentialIssuerService credentialIssuerService,
            ConfigurationService configurationService,
            IpvSessionService ipvSessionService,
            AuditService auditService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            IpvSessionService ipvSessionService) {
        this.credentialIssuerService = credentialIssuerService;
        this.configurationService = configurationService;
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerReturnHandler() {
        this.configurationService = new ConfigurationService();
        this.credentialIssuerService =
                new CredentialIssuerService(
                        configurationService,
                        new KmsEs256Signer(configurationService.getSigningKeyId()));
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(configurationService.getAudienceForClients());
        this.ipvSessionService = new IpvSessionService(configurationService);
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
                LOGGER.error("Validation failed: {}", errorResponse.get().getMessage());
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
            }
            CredentialIssuerConfig credentialIssuerConfig = getCredentialIssuerConfig(request);

            BearerAccessToken accessToken =
                    credentialIssuerService.exchangeCodeForToken(request, credentialIssuerConfig);
            SignedJWT verifiableCredential =
                    credentialIssuerService.getVerifiableCredential(
                            accessToken, credentialIssuerConfig);

            verifiableCredentialJwtValidator.validate(
                    verifiableCredential,
                    credentialIssuerConfig,
                    ipvSessionService
                            .getIpvSession(request.getIpvSessionId())
                            .getClientSessionDetails()
                            .getUserId());

            auditService.sendAuditEvent(
                    AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED);

            auditService.sendAuditEvent(AuditEventTypes.IPV_VC_RECEIVED);

            credentialIssuerService.persistUserCredentials(
                    verifiableCredential.serialize(), request);

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

        if (StringUtils.isBlank(request.getState())) {
            return Optional.of(ErrorResponse.MISSING_OAUTH_STATE);
        }

        if (!request.getState().equals(getPersistedOauthState(request))) {
            return Optional.of(ErrorResponse.INVALID_OAUTH_STATE);
        }

        if (getCredentialIssuerConfig(request) == null) {
            return Optional.of(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }
        return Optional.empty();
    }

    @Tracing
    private String getPersistedOauthState(CredentialIssuerRequestDto request) {
        return ipvSessionService
                .getIpvSession(request.getIpvSessionId())
                .getCredentialIssuerSessionDetails()
                .getState();
    }

    @Tracing
    private CredentialIssuerConfig getCredentialIssuerConfig(CredentialIssuerRequestDto request) {
        return configurationService.getCredentialIssuer(request.getCredentialIssuerId());
    }
}
