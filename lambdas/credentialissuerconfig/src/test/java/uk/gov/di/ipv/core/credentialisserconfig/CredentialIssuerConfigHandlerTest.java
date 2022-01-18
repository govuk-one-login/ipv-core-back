package uk.gov.di.ipv.core.credentialisserconfig;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.credentialissuerconfig.CredentialIssuerConfigHandler;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URI;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerConfigHandlerTest {

    private final Set<CredentialIssuerConfig> credentialIssuerConfigs =
            Set.of(
                    new CredentialIssuerConfig(
                            "test1", URI.create("test1TokenUrl"), URI.create("test1credentialUrl")),
                    new CredentialIssuerConfig(
                            "test2",
                            URI.create("test2TokenUrl"),
                            URI.create("test2credentialUrl")));

    @Mock Context context;

    @Mock ConfigurationService configurationService;

    @Test
    void shouldReceive200ResponseCodeAndListOfCredentialIssuers() throws JsonProcessingException {
        when(configurationService.getCredentialIssuers()).thenReturn(credentialIssuerConfigs);

        CredentialIssuerConfigHandler underTest =
                new CredentialIssuerConfigHandler(configurationService);
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        ObjectMapper objectMapper = new ObjectMapper();
        CredentialIssuerConfig[] responseBody =
                objectMapper.readValue(response.getBody(), CredentialIssuerConfig[].class);

        assertEquals(2, responseBody.length);
        assertArrayEquals(credentialIssuerConfigs.toArray(), responseBody);
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }
}
