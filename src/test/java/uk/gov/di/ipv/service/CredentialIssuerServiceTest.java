package uk.gov.di.ipv.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.UserIssuedCredentialsItem;

import java.net.URI;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@WireMockTest
class CredentialIssuerServiceTest {

    private DataStore<UserIssuedCredentialsItem> mockDataStore;
    private ConfigurationService mockConfigurationService;
    private CredentialIssuerService credentialIssuerService;
    private JSONObject mockJSONObject;

    @BeforeEach
    public void setUp() {
        mockDataStore = mock(DataStore.class);
        mockConfigurationService = mock(ConfigurationService.class);
        mockJSONObject = mock(JSONObject.class);
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

        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
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

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE, exception.getErrorResponse());
    }

    @Test
    public void expectedSuccessWhenSaveCredentials() {

        ArgumentCaptor<UserIssuedCredentialsItem> userIssuedCredentialsItemCaptor = ArgumentCaptor.forClass(UserIssuedCredentialsItem.class);

        CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                "1234",
                "cred_issuer_id_1",
                "http://www.example.com/redirect"
        );

        credentialIssuerService.persistUserCredentials(mockJSONObject,credentialIssuerRequestDto);
        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture());
        verify(mockJSONObject).toJSONString();
        assertEquals(credentialIssuerRequestDto.getIpvSessionId(), userIssuedCredentialsItemCaptor.getValue().getIpvSessionId());
        assertEquals(credentialIssuerRequestDto.getCredentialIssuerId(), userIssuedCredentialsItemCaptor.getValue().getCredentialIssuer());

    }

    @Test
    public void expectedExceptionWhenSaveCredentials() {

        CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                "1234",
                "cred_issuer_id_1",
                "http://www.example.com/redirect"
        );

        doThrow(new UnsupportedOperationException()).when(mockDataStore).create(any());

        CredentialIssuerException thrown = Assertions.assertThrows( CredentialIssuerException.class, () -> {
            credentialIssuerService.persistUserCredentials(mockJSONObject,credentialIssuerRequestDto);
        });

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());

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

        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);;
        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown = assertThrows(CredentialIssuerException.class, () -> {
            credentialIssuerService.getCredential(accessToken, credentialIssuerConfig);
        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
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

        CredentialIssuerConfig credentialIssuerConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);
        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown = assertThrows(CredentialIssuerException.class, () -> {
            credentialIssuerService.getCredential(accessToken, credentialIssuerConfig);
        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    private CredentialIssuerConfig getStubCredentialIssuerConfig(WireMockRuntimeInfo wmRuntimeInfo) {
        return new CredentialIssuerConfig(
                "StubPassport",
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/credential")
        );
    }
}
