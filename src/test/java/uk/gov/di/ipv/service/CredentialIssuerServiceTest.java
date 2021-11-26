package uk.gov.di.ipv.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuerRequestDto;

import java.net.URI;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;

@WireMockTest
class CredentialIssuerServiceTest {

    @Test
    void test_token_response(WireMockRuntimeInfo wmRuntimeInfo) {

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
}