package uk.gov.di.ipv.core.library.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class CredentialIssuerServiceTest {

    private static final String TEST_IPV_SESSION_ID = UUID.randomUUID().toString();

    @Mock private DataStore<UserIssuedCredentialsItem> mockDataStore;
    @Mock private ConfigurationService mockConfigurationService;

    private CredentialIssuerService credentialIssuerService;

    @BeforeEach
    void setUp() throws Exception {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());

        credentialIssuerService =
                new CredentialIssuerService(mockDataStore, mockConfigurationService, signer);
    }

    @Test
    void validTokenResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigurationService.getIpvTokenTtl()).thenReturn("900");
        when(mockConfigurationService.getClientAudience(anyString())).thenReturn("test-audience");
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect");
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                credentialIssuerService.exchangeCodeForToken(
                        credentialIssuerRequestDto, credentialIssuerConfig);
        AccessTokenType type = accessToken.getType();
        assertEquals("Bearer", type.toString());
        assertEquals(3600, accessToken.getLifetime());
        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    }

    @Test
    void tokenErrorResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigurationService.getIpvTokenTtl()).thenReturn("900");
        when(mockConfigurationService.getClientAudience(anyString())).thenReturn("test-audience");
        var errorJson =
                "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}";
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(errorJson)));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect");
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.exchangeCodeForToken(
                                        credentialIssuerRequestDto, credentialIssuerConfig));

        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
    }

    @Test
    void invalidHeaderThrowsCredentialIssuerException(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigurationService.getIpvTokenTtl()).thenReturn("900");
        when(mockConfigurationService.getClientAudience(anyString())).thenReturn("test-audience");
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/xml")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect");
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);
        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.exchangeCodeForToken(
                                        credentialIssuerRequestDto, credentialIssuerConfig));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE, exception.getErrorResponse());
    }

    @Test
    void expectedSuccessWhenSaveCredentials() {
        ArgumentCaptor<UserIssuedCredentialsItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(UserIssuedCredentialsItem.class);

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect");

        credentialIssuerService.persistUserCredentials(SIGNED_VC_1, credentialIssuerRequestDto);
        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture());
        assertEquals(
                credentialIssuerRequestDto.getIpvSessionId(),
                userIssuedCredentialsItemCaptor.getValue().getIpvSessionId());
        assertEquals(
                credentialIssuerRequestDto.getCredentialIssuerId(),
                userIssuedCredentialsItemCaptor.getValue().getCredentialIssuer());
        assertEquals(
                credentialIssuerRequestDto.getCredentialIssuerId(),
                userIssuedCredentialsItemCaptor.getValue().getCredentialIssuer());
        assertEquals(SIGNED_VC_1, userIssuedCredentialsItemCaptor.getValue().getCredential());
    }

    @Test
    void expectedExceptionWhenSaveCredentials() {

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect");

        doThrow(new UnsupportedOperationException()).when(mockDataStore).create(any());

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.persistUserCredentials(
                                        SIGNED_VC_1, credentialIssuerRequestDto));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuer(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=UTF-8")
                                        .withBody(SIGNED_VC_1)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        String credential =
                credentialIssuerService.getVerifiableCredential(
                        accessToken, credentialIssuerConfig, "subject");

        assertEquals(SIGNED_VC_1, credential);

        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCanHandleDerEncodedSignatures(WireMockRuntimeInfo wmRuntimeInfo)
            throws Exception {

        SignedJWT concatEncodedSignedJwt = SignedJWT.parse(SIGNED_VC_1);
        Base64URL transcodedSignatureBase64 =
                Base64URL.encode(
                        ECDSA.transcodeSignatureToDER(
                                concatEncodedSignedJwt.getSignature().decode()));
        String[] jwtParts = concatEncodedSignedJwt.serialize().split("\\.");
        SignedJWT derEncodedSignedJwt =
                SignedJWT.parse(
                        String.format(
                                "%s.%s.%s", jwtParts[0], jwtParts[1], transcodedSignatureBase64));

        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=UTF-8")
                                        .withBody(derEncodedSignedJwt.serialize())));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        String credential =
                credentialIssuerService.getVerifiableCredential(
                        accessToken, credentialIssuerConfig, "subject");

        assertEquals(SIGNED_VC_1, credential);
    }

    @Test
    void getVerifiableCredentialThrowsIfResponseIsNotOk(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withStatus(500)
                                        .withHeader("Content-Type", "text/plain")
                                        .withBody("Something bad happened...")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.getVerifiableCredential(
                                        accessToken, credentialIssuerConfig, "subject"));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIfNotValidSignature(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=UTF-8")
                                        .withBody(SIGNED_VC_1 + "THISWILLBREAKTHESIGNATURE")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);
        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.getVerifiableCredential(
                                        accessToken, credentialIssuerConfig, "subject"));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIfNotValidPublicKey(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=UTF-8")
                                        .withBody(SIGNED_VC_1)));

        CredentialIssuerConfig credentialIssuerConfig =
                new CredentialIssuerConfig(
                        "StubPassport",
                        "any",
                        URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                        URI.create(
                                "http://localhost:"
                                        + wmRuntimeInfo.getHttpPort()
                                        + "/credentials/issue"),
                        URI.create(
                                "http://localhost:"
                                        + wmRuntimeInfo.getHttpPort()
                                        + "/authorizeUrl"),
                        "ipv-core",
                        "NOT A KEY");
        ;

        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.getVerifiableCredential(
                                        accessToken, credentialIssuerConfig, "subject"));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_JWK, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIfNotResponseContentType(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=UTF-8")
                                        .withBody(SIGNED_VC_1)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);
        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.getVerifiableCredential(
                                        accessToken, credentialIssuerConfig, "subject"));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    private CredentialIssuerConfig getStubCredentialIssuerConfig(
            WireMockRuntimeInfo wmRuntimeInfo) {
        return new CredentialIssuerConfig(
                "StubPassport",
                "any",
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                URI.create(
                        "http://localhost:" + wmRuntimeInfo.getHttpPort() + "/credentials/issue"),
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/authorizeUrl"),
                "ipv-core",
                EC_PUBLIC_JWK);
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
