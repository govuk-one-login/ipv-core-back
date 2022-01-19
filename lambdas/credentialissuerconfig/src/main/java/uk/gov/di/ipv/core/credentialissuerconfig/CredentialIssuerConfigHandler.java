package uk.gov.di.ipv.core.credentialissuerconfig;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ParseCredentialIssuerConfigException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.List;

public class CredentialIssuerConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private static final Logger LOGGER =
            LoggerFactory.getLogger(CredentialIssuerConfigHandler.class);

    static {
        System.setProperty(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    public CredentialIssuerConfigHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public CredentialIssuerConfigHandler() {
        configurationService = new ConfigurationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            List<CredentialIssuerConfig> config = configurationService.getCredentialIssuers();
            return ApiGatewayResponseGenerator.proxyJsonResponse(200, config);
        } catch (ParseCredentialIssuerConfigException e) {
            String errorMessage =
                    String.format("Failed to load credential issuer config: %s", e.getMessage());
            LOGGER.error(errorMessage);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    500, ErrorResponse.FAILED_TO_PARSE_CREDENTIAL_ISSUER_CONFIG);
        }
    }
}
