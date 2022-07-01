package uk.gov.di.ipv.core.credentialissuererror;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerErrorDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Arrays;
import java.util.List;

public class CredentialIssuerErrorHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String ERROR_JOURNEY_STEP_URI = "/journey/error";
    private static final List<String> ALLOWED_OAUTH_ERROR_CODES =
            Arrays.asList(
                    OAuth2Error.INVALID_REQUEST_CODE,
                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE,
                    OAuth2Error.ACCESS_DENIED_CODE,
                    OAuth2Error.UNSUPPORTED_RESPONSE_TYPE_CODE,
                    OAuth2Error.INVALID_SCOPE_CODE,
                    OAuth2Error.SERVER_ERROR_CODE,
                    OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE);

    private final ConfigurationService configurationService;
    private final AuditService auditService;

    public CredentialIssuerErrorHandler(
            ConfigurationService configurationService, AuditService auditService) {
        this.configurationService = configurationService;
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerErrorHandler() {
        this.configurationService = new ConfigurationService();
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            RequestHelper.getIpvSessionId(input);
            CredentialIssuerErrorDto credentialIssuerErrorDto =
                    RequestHelper.convertRequest(input, CredentialIssuerErrorDto.class);
            LogHelper.attachCriIdToLogs(credentialIssuerErrorDto.getCredentialIssuerId());

            if (!ALLOWED_OAUTH_ERROR_CODES.contains(credentialIssuerErrorDto.getError())) {
                LOGGER.error("Unknown Oauth error code received");
            }
            LogHelper.logOauthError(
                    "OAuth error received from CRI",
                    credentialIssuerErrorDto.getError(),
                    credentialIssuerErrorDto.getErrorDescription());

            sendAuditEvent(credentialIssuerErrorDto);

            JourneyResponse journeyResponse = new JourneyResponse(ERROR_JOURNEY_STEP_URI);

            return ApiGatewayResponseGenerator.proxyJsonResponse(200, journeyResponse);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }

    private void sendAuditEvent(CredentialIssuerErrorDto credentialIssuerErrorDto) {
        try {
            AuditExtensionErrorParams extensions =
                    new AuditExtensionErrorParams.Builder()
                            .setErrorCode(credentialIssuerErrorDto.getError())
                            .setErrorDescription(credentialIssuerErrorDto.getErrorDescription())
                            .build();
            this.auditService.sendAuditEvent(
                    AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, extensions);
        } catch (SqsException e) {
            LOGGER.error("Failed to write event to audit queue");
        }
    }
}
