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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ParseCredentialIssuerConfigException;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerConfigHandlerTest {

    private final List<CredentialIssuerConfig> credentialIssuerConfigList =
            List.of(
                    new CredentialIssuerConfig(
                            "test1",
                            "Any",
                            URI.create("test1TokenUrl"),
                            URI.create("test1credentialUrl"),
                            URI.create("tesstAuthorizeUrl"),
                            "ipv-core"),
                    new CredentialIssuerConfig(
                            "test2",
                            "Any",
                            URI.create("test2TokenUrl"),
                            URI.create("test2credentialUrl"),
                            URI.create("tesstAuthorizeUrl"),
                            "ipv-core"));
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock Context context;

    @Mock ConfigurationService configurationService;

    @Test
    void shouldReceive200ResponseCodeAndListOfCredentialIssuers()
            throws JsonProcessingException, ParseCredentialIssuerConfigException {
        when(configurationService.getCredentialIssuers()).thenReturn(credentialIssuerConfigList);

        CredentialIssuerConfigHandler underTest =
                new CredentialIssuerConfigHandler(configurationService);
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        CredentialIssuerConfig[] responseBody =
                objectMapper.readValue(response.getBody(), CredentialIssuerConfig[].class);

        assertEquals(2, responseBody.length);
        assertArrayEquals(credentialIssuerConfigList.toArray(), responseBody);
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReceive500ResponseCodeIfUnableToGetCredentialIssuers()
            throws JsonProcessingException, ParseCredentialIssuerConfigException {
        when(configurationService.getCredentialIssuers())
                .thenThrow(new ParseCredentialIssuerConfigException("Something went wrong"));

        CredentialIssuerConfigHandler underTest =
                new CredentialIssuerConfigHandler(configurationService);
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_CREDENTIAL_ISSUER_CONFIG.getCode(),
                responseBody.get("code"));

        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_CREDENTIAL_ISSUER_CONFIG.getMessage(),
                responseBody.get("message"));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, response.getStatusCode());
    }
}
