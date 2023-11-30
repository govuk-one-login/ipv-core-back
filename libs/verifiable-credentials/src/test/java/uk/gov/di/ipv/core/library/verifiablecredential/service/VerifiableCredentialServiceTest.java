package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.VC_TTL;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DCMAW_SUCCESS_RESPONSE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class VerifiableCredentialServiceTest {
    private static final String TEST_AUTH_CODE = "test-auth-code";

    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private ConfigService mockConfigService;

    private VerifiableCredentialService verifiableCredentialService;
    private final String testApiKey = "test-api-key";
    private final String cri = "ukPassport";
    private final String dcmaw_cri = "dcmaw";

    @BeforeEach
    void setUp() {
        verifiableCredentialService =
                new VerifiableCredentialService(mockDataStore, mockConfigService);
    }

    //    @Test
    //    void validTokenResponse(WireMockRuntimeInfo wmRuntimeInfo) {
    //        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
    //        stubFor(
    //                post("/token")
    //                        .willReturn(
    //                                aResponse()
    //                                        .withHeader(
    //                                                "Content-Type",
    // "application/json;charset=utf-8")
    //                                        .withBody(
    //
    // "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));
    //
    //        CredentialIssuerConfig credentialIssuerConfig =
    //                getStubCredentialIssuerConfig(wmRuntimeInfo);
    //
    //        AccessToken accessToken =
    //                verifiableCredentialService.exchangeCodeForToken(
    //                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey, cri);
    //        AccessTokenType type = accessToken.getType();
    //        assertEquals("Bearer", type.toString());
    //        assertEquals(3600, accessToken.getLifetime());
    //        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    //    }

    //    @Test
    //    void validTokenResponseForAppJourney(WireMockRuntimeInfo wmRuntimeInfo) {
    //        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
    //        stubFor(
    //                post("/token")
    //                        .willReturn(
    //                                aResponse()
    //                                        .withHeader(
    //                                                "Content-Type",
    // "application/json;charset=utf-8")
    //                                        .withBody(
    //
    // "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));
    //
    //        CredentialIssuerConfig credentialIssuerConfig =
    //                getStubCredentialIssuerConfig(wmRuntimeInfo);
    //
    //        AccessToken accessToken =
    //                verifiableCredentialService.exchangeCodeForToken(
    //                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey, cri);
    //        AccessTokenType type = accessToken.getType();
    //        assertEquals("Bearer", type.toString());
    //        assertEquals(3600, accessToken.getLifetime());
    //        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    //    }

    //    @Test
    //    void validTokenResponseWithoutApiKey(WireMockRuntimeInfo wmRuntimeInfo) {
    //        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
    //        stubFor(
    //                post("/token")
    //                        .willReturn(
    //                                aResponse()
    //                                        .withHeader(
    //                                                "Content-Type",
    // "application/json;charset=utf-8")
    //                                        .withBody(
    //
    // "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));
    //
    //        CredentialIssuerConfig credentialIssuerConfig =
    //                getStubCredentialIssuerConfig(wmRuntimeInfo);
    //
    //        AccessToken accessToken =
    //                verifiableCredentialService.exchangeCodeForToken(
    //                        TEST_AUTH_CODE, credentialIssuerConfig, null, cri);
    //        AccessTokenType type = accessToken.getType();
    //        assertEquals("Bearer", type.toString());
    //        assertEquals(3600, accessToken.getLifetime());
    //        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    //    }

    //    @Test
    //    void tokenErrorResponse(WireMockRuntimeInfo wmRuntimeInfo) {
    //        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
    //        var errorJson =
    //                "{ \"error\": \"invalid_request\", \"error_description\": \"Request was
    // missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at
    // https://authorization-server.com/docs/access_token\"}";
    //        stubFor(
    //                post("/token")
    //                        .willReturn(
    //                                aResponse()
    //                                        .withStatus(400)
    //                                        .withHeader(
    //                                                "Content-Type",
    // "application/json;charset=utf-8")
    //                                        .withBody(errorJson)));
    //
    //        CredentialIssuerConfig credentialIssuerConfig =
    //                getStubCredentialIssuerConfig(wmRuntimeInfo);
    //
    //        VerifiableCredentialException exception =
    //                assertThrows(
    //                        VerifiableCredentialException.class,
    //                        () ->
    //                                verifiableCredentialService.exchangeCodeForToken(
    //                                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey,
    // cri));
    //
    //        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
    //        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
    //    }

    //    @Test
    //    void invalidHeaderThrowsCredentialIssuerException(WireMockRuntimeInfo wmRuntimeInfo) {
    //        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
    //        stubFor(
    //                post("/token")
    //                        .willReturn(
    //                                aResponse()
    //                                        .withHeader("Content-Type",
    // "application/xml;charset=utf-8")
    //                                        .withBody(
    //
    // "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));
    //
    //        CredentialIssuerConfig credentialIssuerConfig =
    //                getStubCredentialIssuerConfig(wmRuntimeInfo);
    //        CredentialIssuerException exception =
    //                assertThrows(
    //                        CredentialIssuerException.class,
    //                        () ->
    //                                verifiableCredentialService.exchangeCodeForToken(
    //                                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey,
    // cri));
    //
    //        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
    //        assertEquals(
    //                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE,
    // exception.getErrorResponse());
    //    }

    @Test
    void expectedSuccessWhenSaveCredentials() throws Exception {
        ArgumentCaptor<VcStoreItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(VcStoreItem.class);

        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        verifiableCredentialService.persistUserCredentials(
                SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL), credentialIssuerId, userId);
        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture(), eq(VC_TTL));
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();
        assertEquals(userId, vcStoreItem.getUserId());
        assertEquals(credentialIssuerId, vcStoreItem.getCredentialIssuer());
        assertEquals(Instant.parse("2022-05-20T12:50:54Z"), vcStoreItem.getExpirationTime());
        assertEquals(VC_PASSPORT_NON_DCMAW_SUCCESSFUL, vcStoreItem.getCredential());
    }

    @Test
    void expectedSuccessWithoutExpWhenSaveCredentials() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                        new JWTClaimsSet.Builder()
                                .subject("testSubject")
                                .issuer(credentialIssuerId)
                                .build());
        signedJwt.sign(new ECDSASigner(getPrivateKey()));

        ArgumentCaptor<VcStoreItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(VcStoreItem.class);

        verifiableCredentialService.persistUserCredentials(signedJwt, credentialIssuerId, userId);

        verify(mockDataStore).create(userIssuedCredentialsItemCaptor.capture(), eq(VC_TTL));
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();

        assertNull(vcStoreItem.getExpirationTime());
        assertEquals(userId, vcStoreItem.getUserId());
        assertEquals(credentialIssuerId, vcStoreItem.getCredentialIssuer());
        assertEquals(signedJwt.serialize(), vcStoreItem.getCredential());
        verify(mockDataStore, Mockito.times(1)).create(any(), any());
    }

    @Test
    void expectedExceptionWhenSaveCredentials() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        doThrow(new UnsupportedOperationException()).when(mockDataStore).create(any(), any());

        SignedJWT signedJwt = SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL);
        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
    }

    @Test
    void expectedExceptionWithoutAnySignerWhenSaveCredentialsForIllegalStateException() {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                        new JWTClaimsSet.Builder().expirationTime(new Date()).build());

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
        verify(mockDataStore, Mockito.times(0)).create(any(), any());
    }

    @Test
    void expectedExceptionWhenSaveCredentialsForParseException() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        SignedJWT signedJwt = Mockito.mock(SignedJWT.class);

        when(signedJwt.serialize()).thenReturn("credential-serialize");
        when(signedJwt.getJWTClaimsSet()).thenThrow(java.text.ParseException.class);

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.persistUserCredentials(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
        verify(mockDataStore, Mockito.times(0)).create(any(), any());
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuer(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(VC_PASSPORT_NON_DCMAW_SUCCESSFUL)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        VerifiableCredentialResponse verifiableCredentialResponse =
                verifiableCredentialService.getVerifiableCredentialResponse(
                        accessToken, credentialIssuerConfig, testApiKey, cri);

        assertEquals(
                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                verifiableCredentialResponse.getVerifiableCredentials().get(0).serialize());

        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyGetsAPendingResponseFromCredentialIssuer(
            WireMockRuntimeInfo wmRuntimeInfo) {
        final String testUserId = "urn:uuid" + UUID.randomUUID();
        final String pendingResponse =
                "{\"sub\":\""
                        + testUserId
                        + "\",\"https://vocab.account.gov.uk/v1/credentialStatus\":\"pending\"}";
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(pendingResponse)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        VerifiableCredentialResponse verifiableCredentialResponse =
                verifiableCredentialService.getVerifiableCredentialResponse(
                        accessToken, credentialIssuerConfig, testApiKey, cri);

        assertEquals(testUserId, verifiableCredentialResponse.getUserId());
        assertEquals(
                VerifiableCredentialStatus.PENDING,
                verifiableCredentialResponse.getCredentialStatus());

        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuerWithoutApiKey(
            WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(VC_PASSPORT_NON_DCMAW_SUCCESSFUL)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        VerifiableCredentialResponse verifiableCredentialResponse =
                verifiableCredentialService.getVerifiableCredentialResponse(
                        accessToken, credentialIssuerConfig, null, cri);

        assertEquals(
                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                verifiableCredentialResponse.getVerifiableCredentials().get(0).serialize());

        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsCriAndCanHandleJsonResponse(
            WireMockRuntimeInfo wmRuntimeInfo) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                objectMapper.writeValueAsString(
                                                        DCMAW_SUCCESS_RESPONSE))));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        VerifiableCredentialResponse verifiableCredentialResponse =
                verifiableCredentialService.getVerifiableCredentialResponse(
                        accessToken, credentialIssuerConfig, null, cri);

        assertEquals(
                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                verifiableCredentialResponse.getVerifiableCredentials().get(0).serialize());

        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
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

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.getVerifiableCredentialResponse(
                                        accessToken, credentialIssuerConfig, testApiKey, cri));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIf404NotFoundFromDcmawCri(WireMockRuntimeInfo wmRuntimeInfo) {

        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withStatus(404)
                                        .withHeader("Content-Type", "text/plain")
                                        .withBody("Something bad happened...")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.getVerifiableCredentialResponse(
                                        accessToken,
                                        credentialIssuerConfig,
                                        testApiKey,
                                        dcmaw_cri));

        assertEquals(HTTPResponse.SC_NOT_FOUND, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIfNotResponseContentType(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(VC_PASSPORT_NON_DCMAW_SUCCESSFUL)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);
        BearerAccessToken accessToken = new BearerAccessToken();

        VerifiableCredentialException thrown =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                verifiableCredentialService.getVerifiableCredentialResponse(
                                        accessToken, credentialIssuerConfig, testApiKey, cri));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    private CredentialIssuerConfig getStubCredentialIssuerConfig(
            WireMockRuntimeInfo wmRuntimeInfo) {
        return new CredentialIssuerConfig(
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                URI.create(
                        "http://localhost:" + wmRuntimeInfo.getHttpPort() + "/credentials/issue"),
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/authorizeUrl"),
                "ipv-core",
                EC_PUBLIC_JWK,
                RSA_ENCRYPTION_PUBLIC_JWK,
                "test-audience",
                URI.create(
                        "http://localhost:"
                                + wmRuntimeInfo.getHttpPort()
                                + "/credential-issuer/callback?id=StubPassport"),
                true,
                false);
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
