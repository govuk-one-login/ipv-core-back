package uk.gov.di.ipv.core.buildcrioauthrequest.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.EvidenceRequest;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponse;
import uk.gov.di.ipv.core.library.domain.SocialSecurityRecord;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_JWT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class AuthorizationRequestHelperTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String CLIENT_ID_FIELD = "client_id";
    private static final String IPV_CLIENT_ID_VALUE = "testClientId";
    private static final String IPV_ISSUER = "http://example.com/issuer";
    private static final String AUDIENCE = "Audience";
    private static final String TEST_CONTEXT = "test_context";
    private static final EvidenceRequest TEST_EVIDENCE_REQUEST = new EvidenceRequest("gpg45", 2);
    private static final String IPV_TOKEN_TTL = "900";
    private static final String MOCK_CORE_FRONT_CALLBACK_URL = "callbackUri";
    private static final String TEST_REDIRECT_URI = "http:example.com/callback/criId";
    private static final String CRI_ID = "cri_id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_SHARED_CLAIMS = "shared_claims";
    private static final String TEST_EMAIL_ADDRESS = "test@hotmail.com";
    private static final String OAUTH_STATE = SecureTokenHelper.getInstance().generate();

    private final SharedClaimsResponse sharedClaims =
            new SharedClaimsResponse(
                    Set.of(new Name(List.of(new NameParts("Dan", "first_name")))),
                    Set.of(new BirthDate("2011-01-01")),
                    Set.of(new Address()),
                    TEST_EMAIL_ADDRESS,
                    Set.of(new SocialSecurityRecord()));

    private ECDSASigner signer;

    @Mock JWSSigner jwsSigner;

    @Mock OauthCriConfig oauthCriConfig;

    @Mock ConfigService configService;

    private RSAEncrypter rsaEncrypter;

    @BeforeEach
    void setUp()
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException,
                    ParseException {
        signer = new ECDSASigner(getPrivateKey());
        rsaEncrypter = new RSAEncrypter((RSAPublicKey) getEncryptionPublicKey());
    }

    @Test
    void shouldCreateSignedJWTWithCorrectClaims()
            throws JOSEException, ParseException, HttpResponseExceptionWithErrorBody {
        setupCredentialIssuerConfigMock();
        setupConfigurationServiceMock();
        when(oauthCriConfig.getComponentId()).thenReturn(AUDIENCE);
        when(oauthCriConfig.getClientCallbackUrl()).thenReturn(URI.create(TEST_REDIRECT_URI));

        SignedJWT result =
                AuthorizationRequestHelper.createSignedJWT(
                        sharedClaims,
                        signer,
                        oauthCriConfig,
                        configService,
                        OAUTH_STATE,
                        TEST_USER_ID,
                        TEST_JOURNEY_ID,
                        null,
                        null);

        assertEquals(IPV_ISSUER, result.getJWTClaimsSet().getIssuer());
        assertEquals(TEST_USER_ID, result.getJWTClaimsSet().getSubject());
        assertEquals(
                TEST_JOURNEY_ID,
                result.getJWTClaimsSet().getStringClaim("govuk_signin_journey_id"));
        assertEquals(AUDIENCE, result.getJWTClaimsSet().getAudience().get(0));
        assertEquals(sharedClaims, result.getJWTClaimsSet().getClaims().get(TEST_SHARED_CLAIMS));
        assertEquals(OAUTH_STATE, result.getJWTClaimsSet().getClaim("state"));
        assertEquals(
                IPV_CLIENT_ID_VALUE, result.getJWTClaimsSet().getClaims().get(CLIENT_ID_FIELD));
        assertEquals(TEST_REDIRECT_URI, result.getJWTClaimsSet().getClaims().get("redirect_uri"));
        assertTrue(result.verify(new ECDSAVerifier(ECKey.parse(TEST_EC_PUBLIC_JWK))));
    }

    @ParameterizedTest
    @MethodSource("journeyUriParameters")
    void shouldCreateSignedJWTWithGivenParameters(
            String context, EvidenceRequest evidenceRequest, Map<String, Object> expectedClaims)
            throws ParseException, HttpResponseExceptionWithErrorBody {
        setupCredentialIssuerConfigMock();
        setupConfigurationServiceMock();
        when(oauthCriConfig.getComponentId()).thenReturn(AUDIENCE);
        when(oauthCriConfig.getClientCallbackUrl()).thenReturn(URI.create(TEST_REDIRECT_URI));

        SignedJWT result =
                AuthorizationRequestHelper.createSignedJWT(
                        sharedClaims,
                        signer,
                        oauthCriConfig,
                        configService,
                        OAUTH_STATE,
                        TEST_USER_ID,
                        TEST_JOURNEY_ID,
                        evidenceRequest,
                        context);

        for (Map.Entry<String, Object> entry : expectedClaims.entrySet()) {
            var actual = result.getJWTClaimsSet().getClaim(entry.getKey());
            assertEquals(
                    entry.getValue(),
                    actual,
                    () ->
                            String.format(
                                    "Expected claim for key=%s to be %s, but found %s",
                                    entry.getKey(), entry.getValue(), actual));
        }
    }

    private static Stream<Arguments> journeyUriParameters() {
        return Stream.of(
                Arguments.of(TEST_CONTEXT, null, Map.of("context", TEST_CONTEXT)),
                Arguments.of(
                        null,
                        TEST_EVIDENCE_REQUEST,
                        Map.of("evidence_requested", TEST_EVIDENCE_REQUEST)),
                Arguments.of(
                        TEST_CONTEXT,
                        TEST_EVIDENCE_REQUEST,
                        Map.of(
                                "context",
                                TEST_CONTEXT,
                                "evidence_requested",
                                TEST_EVIDENCE_REQUEST)));
    }

    @Test
    void shouldCreateSignedJWTWithCorrectEvidenceRequest()
            throws ParseException, HttpResponseExceptionWithErrorBody, JsonProcessingException {
        setupCredentialIssuerConfigMock();
        setupConfigurationServiceMock();
        when(oauthCriConfig.getComponentId()).thenReturn(AUDIENCE);
        when(oauthCriConfig.getClientCallbackUrl()).thenReturn(URI.create(TEST_REDIRECT_URI));

        var result =
                AuthorizationRequestHelper.createSignedJWT(
                        sharedClaims,
                        signer,
                        oauthCriConfig,
                        configService,
                        OAUTH_STATE,
                        TEST_USER_ID,
                        TEST_JOURNEY_ID,
                        new EvidenceRequest("gpg45", 2),
                        null);

        var evidenceRequested = result.getJWTClaimsSet().getClaim("evidence_requested");
        var evidenceRequestedJson = objectMapper.writeValueAsString(evidenceRequested);
        assertEquals("{\"scoringPolicy\":\"gpg45\",\"strengthScore\":2}", evidenceRequestedJson);
    }

    @Test
    void shouldCreateSignedJWTWithCorrectPartialEvidenceRequest()
            throws ParseException, HttpResponseExceptionWithErrorBody, JsonProcessingException {
        setupCredentialIssuerConfigMock();
        setupConfigurationServiceMock();
        when(oauthCriConfig.getComponentId()).thenReturn(AUDIENCE);
        when(oauthCriConfig.getClientCallbackUrl()).thenReturn(URI.create(TEST_REDIRECT_URI));

        var result =
                AuthorizationRequestHelper.createSignedJWT(
                        sharedClaims,
                        signer,
                        oauthCriConfig,
                        configService,
                        OAUTH_STATE,
                        TEST_USER_ID,
                        TEST_JOURNEY_ID,
                        new EvidenceRequest(null, 2),
                        null);

        var evidenceRequested = result.getJWTClaimsSet().getClaim("evidence_requested");
        var evidenceRequestedJson = objectMapper.writeValueAsString(evidenceRequested);
        assertEquals("{\"strengthScore\":2}", evidenceRequestedJson);
    }

    @Test
    void shouldNotReturnSharedClaimsIfSharedClaimsMapIsEmpty()
            throws ParseException, HttpResponseExceptionWithErrorBody {
        setupCredentialIssuerConfigMock();
        setupConfigurationServiceMock();

        SignedJWT result =
                AuthorizationRequestHelper.createSignedJWT(
                        null,
                        signer,
                        oauthCriConfig,
                        configService,
                        OAUTH_STATE,
                        TEST_USER_ID,
                        TEST_JOURNEY_ID,
                        null,
                        null);
        assertNull(result.getJWTClaimsSet().getClaims().get(TEST_SHARED_CLAIMS));
    }

    @Test
    void shouldThrowExceptionWhenUnableToSignJwt() {
        setupCredentialIssuerConfigMock();
        setupConfigurationServiceMock();

        HttpResponseExceptionWithErrorBody exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                AuthorizationRequestHelper.createSignedJWT(
                                        null,
                                        jwsSigner,
                                        oauthCriConfig,
                                        configService,
                                        OAUTH_STATE,
                                        TEST_USER_ID,
                                        TEST_JOURNEY_ID,
                                        null,
                                        null));
        assertEquals(500, exception.getResponseCode());
        assertEquals("Failed to sign Shared Attributes", exception.getErrorReason());
    }

    @Test
    void shouldCreateJWEObject()
            throws ParseException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException,
                    HttpResponseExceptionWithErrorBody {
        JWEObject result =
                AuthorizationRequestHelper.createJweObject(
                        rsaEncrypter, SignedJWT.parse(SIGNED_JWT));

        assertEquals(JWEObject.State.ENCRYPTED, result.getState());

        RSADecrypter rsaDecrypter = new RSADecrypter(getEncryptionPrivateKey());
        result.decrypt(rsaDecrypter);
        SignedJWT signedJWT = result.getPayload().toSignedJWT();

        assertEquals(IPV_CLIENT_ID_VALUE, signedJWT.getJWTClaimsSet().getIssuer());
        assertEquals(IPV_CLIENT_ID_VALUE, signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(AUDIENCE, signedJWT.getJWTClaimsSet().getAudience().get(0));
        assertEquals(
                IPV_CLIENT_ID_VALUE, signedJWT.getJWTClaimsSet().getClaims().get(CLIENT_ID_FIELD));
        assertEquals(
                String.format("%s?id=%s", MOCK_CORE_FRONT_CALLBACK_URL, CRI_ID),
                signedJWT.getJWTClaimsSet().getClaims().get("redirect_uri"));
    }

    @Test
    void shouldThrowExceptionWhenUnableToEncryptJwt() {
        HttpResponseExceptionWithErrorBody exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                AuthorizationRequestHelper.createJweObject(
                                        mock(RSAEncrypter.class), SignedJWT.parse(SIGNED_JWT)));
        assertEquals(500, exception.getResponseCode());
        assertEquals("Failed to encrypt JWT", exception.getErrorReason());
    }

    private void setupCredentialIssuerConfigMock() {
        when(oauthCriConfig.getClientId()).thenReturn(IPV_CLIENT_ID_VALUE);
    }

    private void setupConfigurationServiceMock() {
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn(IPV_TOKEN_TTL);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
    }

    private PrivateKey getEncryptionPrivateKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(
                        new PKCS8EncodedKeySpec(
                                Base64.getDecoder().decode(RSA_ENCRYPTION_PRIVATE_KEY)));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }

    private PublicKey getEncryptionPublicKey()
            throws NoSuchAlgorithmException, ParseException, InvalidKeySpecException {
        RSAKey rsaKey = RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK);
        RSAPublicKeySpec rsaPublicKeySpec =
                new RSAPublicKeySpec(
                        rsaKey.getModulus().decodeToBigInteger(),
                        rsaKey.getPublicExponent().decodeToBigInteger());
        return KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
    }
}
