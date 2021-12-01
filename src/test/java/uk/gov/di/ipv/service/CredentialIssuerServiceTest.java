package uk.gov.di.ipv.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.junit.jupiter.api.BeforeEach;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.UserIssuedCredentialsItem;

import java.net.URI;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@WireMockTest
class CredentialIssuerServiceTest {

    private DataStore<UserIssuedCredentialsItem> mockDataStore;
    private ConfigurationService mockConfigurationService;
    private CredentialIssuerService credentialIssuerService;

    @BeforeEach
    public void setUp() {
        mockDataStore = mock(DataStore.class);
        mockConfigurationService = mock(ConfigurationService.class);
        credentialIssuerService = new CredentialIssuerService(mockDataStore, mockConfigurationService);
    }

    @Test
    void test_valid_token_response(WireMockRuntimeInfo wmRuntimeInfo) {

        stubFor(post("/token")
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                "1234",
                "cred_issuer_id_1",
                "http://www.example.com/redirect"
        );
        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken = credentialIssuerService.exchangeCodeForToken(credentialIssuerRequestDto, credentialIssuerConfig);
        AccessTokenType type = accessToken.getType();
        assertEquals("Bearer", type.toString());
        assertEquals(3600, accessToken.getLifetime());
        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());

    }

    @Test
    void test_token_error_response(WireMockRuntimeInfo wmRuntimeInfo) {

        var errorJson = "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}";
        stubFor(post("/token")
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody(errorJson)));

        CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                "1234",
                "cred_issuer_id_1",
                "http://www.example.com/redirect"
        );
        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);

        CredentialIssuerException exception = assertThrows(CredentialIssuerException.class, () -> {
            credentialIssuerService.exchangeCodeForToken(credentialIssuerRequestDto, credentialIssuerConfig);
        });

        String message = exception.getMessage();
        assertEquals("invalid_request: Request was missing the 'redirect_uri' parameter.", message);
    }

    @Test
    void invalidHeaderThrowsCredentialIssuerException(WireMockRuntimeInfo wmRuntimeInfo) {

        stubFor(post("/token")
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/xml")
                        .withBody("{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                "1234",
                "cred_issuer_id_1",
                "http://www.example.com/redirect"
        );
        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);
        CredentialIssuerException exception = assertThrows(CredentialIssuerException.class, () -> {
            credentialIssuerService.exchangeCodeForToken(credentialIssuerRequestDto, credentialIssuerConfig);
        });

        String expectedMessage = "The HTTP Content-Type header must be application/json";
        String actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(expectedMessage));
    }

    @Test
    void getCredentialCorrectlyCallsACredentialIssuer(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get("/credential")
                .willReturn(
                        aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBody("{\"id\": \"some-resource-id\", \"evidenceType\": \"passport\", \"evidenceID\": \"passport-abc-12345\"}")
                )
        );

        CredentialIssuerService credentialIssuerService = new CredentialIssuerService();
        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);;
        BearerAccessToken accessToken = new BearerAccessToken();

        JSONObject credential = credentialIssuerService.getCredential(accessToken, credentialIssuerConfig);

        assertEquals(credential.get("id"), "some-resource-id");
        assertEquals(credential.get("evidenceType"), "passport");
        assertEquals(credential.get("evidenceID"), "passport-abc-12345");

        verify(
                getRequestedFor(
                        urlEqualTo("/credential")
                ).withHeader(
                        "Authorization",
                        equalTo("Bearer " + accessToken.getValue())
                )
        );
    }

    @Test
    void getCredentialThrowsIfResponseIsNotOk(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get("/credential")
                .willReturn(
                        aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "text/plain")
                        .withBody("Something bad happened...")
                )
        );

        CredentialIssuerService credentialIssuerService = new CredentialIssuerService();
        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);;
        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown = assertThrows(CredentialIssuerException.class, () -> {
            credentialIssuerService.getCredential(accessToken, credentialIssuerConfig);
        });

        assertTrue(thrown.getMessage().contains("500: Server Error"));
    }

    @Test
    void getCredentialThrowsIfNotValidJsonInResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get("/credential")
                .willReturn(
                        aResponse()
                        .withHeader("Content-Type", "application/json;charset=UTF-8")
                        .withBody("What on earth is this?")
                )
        );

        CredentialIssuerService credentialIssuerService = new CredentialIssuerService();
        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);
        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown = assertThrows(CredentialIssuerException.class, () -> {
            credentialIssuerService.getCredential(accessToken, credentialIssuerConfig);
        });

        assertTrue(thrown.getMessage().contains("ParseException: Invalid JSON: Unexpected token What on earth is this?"));
    }

    private CredentialIssuerConfig getStubCredentialIssuerConfig(WireMockRuntimeInfo wmRuntimeInfo) {
        return new CredentialIssuerConfig(
                "StubPassport",
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/credential")
        );
    }
}
