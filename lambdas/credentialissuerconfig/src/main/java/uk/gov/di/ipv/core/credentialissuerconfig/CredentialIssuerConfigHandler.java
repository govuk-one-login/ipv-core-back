package uk.gov.di.ipv.core.credentialissuerconfig;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.List;

public class CredentialIssuerConfigHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;

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

        List<CredentialIssuerConfig> config = configurationService.getCredentialIssuers();

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, config);
    }
}
