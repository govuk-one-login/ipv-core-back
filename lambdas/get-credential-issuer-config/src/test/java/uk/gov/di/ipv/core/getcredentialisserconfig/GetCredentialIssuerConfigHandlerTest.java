package uk.gov.di.ipv.core.getcredentialisserconfig;

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
import uk.gov.di.ipv.core.getcredentialissuerconfig.GetCredentialIssuerConfigHandler;
import uk.gov.di.ipv.core.library.credentialissuer.CredentialIssuerConfigService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ParseCredentialIssuerConfigException;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class GetCredentialIssuerConfigHandlerTest {

    private final List<CredentialIssuerConfig> credentialIssuerConfigList =
            List.of(
                    new CredentialIssuerConfig(
                            "test1",
                            "Any",
                            true,
                            URI.create("test1TokenUrl"),
                            URI.create("test1credentialUrl"),
                            URI.create("test1AuthorizeUrl"),
                            "ipv-core",
                            EC_PUBLIC_JWK,
                            RSA_ENCRYPTION_PUBLIC_JWK,
                            "test-audience",
                            URI.create("testRedirectUrl"),
                            "name, address"),
                    new CredentialIssuerConfig(
                            "test2",
                            "Any",
                            true,
                            URI.create("test2TokenUrl"),
                            URI.create("test2credentialUrl"),
                            URI.create("test2AuthorizeUrl"),
                            "ipv-core",
                            EC_PUBLIC_JWK,
                            RSA_ENCRYPTION_PUBLIC_JWK,
                            "test-audience",
                            URI.create("test2RedirectUrl"),
                            "name, address"));

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock Context context;
    @Mock CredentialIssuerConfigService credentialIssuerConfigService;

    @Test
    void shouldReceive200ResponseCodeAndListOfCredentialIssuers()
            throws JsonProcessingException, ParseCredentialIssuerConfigException {
        when(credentialIssuerConfigService.getCredentialIssuers())
                .thenReturn(credentialIssuerConfigList);

        GetCredentialIssuerConfigHandler underTest =
                new GetCredentialIssuerConfigHandler(credentialIssuerConfigService);
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

        when(credentialIssuerConfigService.getCredentialIssuers())
                .thenThrow(new ParseCredentialIssuerConfigException("Something went wrong"));

        GetCredentialIssuerConfigHandler underTest =
                new GetCredentialIssuerConfigHandler(credentialIssuerConfigService);
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
