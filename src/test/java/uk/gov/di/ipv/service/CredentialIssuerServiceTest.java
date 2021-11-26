package uk.gov.di.ipv.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;

import java.net.URI;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.*;

@WireMockTest
class CredentialIssuerServiceTest {

    @Test
    void test_valid_token_response(WireMockRuntimeInfo wmRuntimeInfo) {

        stubFor(post("/token")
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerService credentialIssuerService = new CredentialIssuerService();
        CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                "1234",
                "cred_issuer_id_1",
                "http://www.example.com/redirect"
        );
        CredentialIssuerConfig credentialIssuerConfig = new CredentialIssuerConfig(
                "StubPassport",
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"));

        AccessToken accessToken = credentialIssuerService.exchangeCodeForToken(credentialIssuerRequestDto, credentialIssuerConfig);
        AccessTokenType type = accessToken.getType();
        assertEquals("Bearer", type.toString());
        assertEquals(3600, accessToken.getLifetime());
        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());

    }

    @Test
    void test_token_error_response(WireMockRuntimeInfo wmRuntimeInfo) {

        CredentialIssuerException exception = assertThrows(CredentialIssuerException.class, () -> {
            var errorJson = "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}";
            stubFor(post("/token")
                    .willReturn(aResponse()
                            .withStatus(400)
                            .withHeader("Content-Type", "application/json")
                            .withBody(errorJson)));

            CredentialIssuerService credentialIssuerService = new CredentialIssuerService();
            CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                    "1234",
                    "cred_issuer_id_1",
                    "http://www.example.com/redirect"
            );
            CredentialIssuerConfig credentialIssuerConfig = new CredentialIssuerConfig(
                    "StubPassport",
                    URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"));

            AccessToken accessToken = credentialIssuerService.exchangeCodeForToken(credentialIssuerRequestDto, credentialIssuerConfig);

            AccessTokenType type = accessToken.getType();
            assertEquals("Bearer", type.toString());
            assertEquals(3600, accessToken.getLifetime());
            assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
        });

        String message = exception.getMessage();
        assertEquals("invalid_request: Request was missing the 'redirect_uri' parameter.", message);
    }

    @Test
    public void invalidHeaderThrowsCredentialIssuerException(WireMockRuntimeInfo wmRuntimeInfo) {

        RuntimeException exception = assertThrows(CredentialIssuerException.class, () -> {
            stubFor(post("/token")
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "application/xml")
                            .withBody("{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

            CredentialIssuerService credentialIssuerService = new CredentialIssuerService();
            CredentialIssuerRequestDto credentialIssuerRequestDto = new CredentialIssuerRequestDto(
                    "1234",
                    "cred_issuer_id_1",
                    "http://www.example.com/redirect"
            );
            CredentialIssuerConfig credentialIssuerConfig = new CredentialIssuerConfig(
                    "StubPassport",
                    URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"));;
            AccessToken accessToken = credentialIssuerService.exchangeCodeForToken(credentialIssuerRequestDto, credentialIssuerConfig);

        });

        String expectedMessage = "The HTTP Content-Type header must be application/json";
        String actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(expectedMessage));
    }




    }


