package uk.gov.di.ipv.core.credentialissuererror;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerErrorDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

public class CredentialIssuerErrorHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(CredentialIssuerErrorHandler.class.getName());

    private static final String ERROR_JOURNEY_STEP_URI = "/journey/error";

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
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        CredentialIssuerErrorDto credentialIssuerErrorDto =
                RequestHelper.convertRequest(input, CredentialIssuerErrorDto.class);

        LOGGER.error(
                "An error occurred with the {} cri",
                credentialIssuerErrorDto.getCredentialIssuerId());
        LOGGER.error("Error code: {}", credentialIssuerErrorDto.getError());
        LOGGER.error(credentialIssuerErrorDto.getErrorDescription());

        try {
            this.auditService.sendAuditEvent(AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED);
        } catch (SqsException e) {
            LOGGER.error("Failed to write event to audit queue");
        }

        JourneyResponse journeyResponse = new JourneyResponse(ERROR_JOURNEY_STEP_URI);

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, journeyResponse);
    }
}
