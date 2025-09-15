package uk.gov.di.ipv.core.issueclientaccesstoken.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import uk.gov.di.ipv.core.issueclientaccesstoken.exception.ClientAuthenticationException;
import uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class TokenRequestValidatorTest {

    private static final String CLIENT_ID = "di-ipv-orchestrator-stub";
    private static final String TEST_JTI = "test-jti";

    @Mock private ConfigService mockConfigService;
    @Mock private ClientAuthJwtIdService mockClientAuthJwtIdService;
    @Mock private OAuthKeyService mockOAuthKeyService;
    @InjectMocks private TokenRequestValidator validator;

    @BeforeEach
    void setUp() {
        when(mockConfigService.getComponentId()).thenReturn("https://core-component.example");
    }

    @Test
    void shouldNotThrowForValidJwt() throws Exception {
        when(mockConfigService.getMaxAllowedAuthClientTtl()).thenReturn(2400L);
        when(mockOAuthKeyService.getClientSigningKey(any(), any()))
                .thenReturn(ECKey.parse(TEST_EC_PUBLIC_JWK));

        var validQueryParams =
                getValidQueryParams(generateClientAssertion(getValidClaimsSetValues()));

        assertDoesNotThrow(() -> validator.authenticateClient(queryMapToString(validQueryParams)));
    }

    @Test
    void shouldThrowIfInvalidSignature() throws Exception {
        when(mockOAuthKeyService.getClientSigningKey(any(), any()))
                .thenReturn(ECKey.parse(TEST_EC_PUBLIC_JWK));

        var invalidSignatureQueryParams =
                new HashMap<>(
                        getValidQueryParams(generateClientAssertion(getValidClaimsSetValues())));
        invalidSignatureQueryParams.put(
                "client_assertion",
                invalidSignatureQueryParams.get("client_assertion") + "BREAKING_THE_SIGNATURE");

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(invalidSignatureQueryParams)));

        assertTrue(exception.getMessage().contains("InvalidClientException: Bad JWT signature"));
    }

    @Test
    void shouldThrowIfClaimsSetIssuerAndSubjectAreNotTheSame() throws Exception {
        var differentIssuerAndSubjectClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        differentIssuerAndSubjectClaimsSetValues.put(
                JWTClaimNames.ISSUER, "NOT_THE_SAME_AS_SUBJECT");
        var differentIssuerAndSubjectQueryParams =
                getValidQueryParams(
                        generateClientAssertion(differentIssuerAndSubjectClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(differentIssuerAndSubjectQueryParams)));

        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "Bad / expired JWT claims: Issuer and subject JWT claims don't match"));
    }

    @Test
    void shouldThrowIfWrongAudience() throws Exception {
        var wrongAudienceClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        wrongAudienceClaimsSetValues.put(
                JWTClaimNames.AUDIENCE, "NOT_THE_AUDIENCE_YOU_ARE_LOOKING_FOR");
        var wrongAudienceQueryParams =
                getValidQueryParams(generateClientAssertion(wrongAudienceClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(wrongAudienceQueryParams)));

        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "Bad / expired JWT claims: JWT audience rejected: [NOT_THE_AUDIENCE_YOU_ARE_LOOKING_FOR]"));
    }

    @Test
    void shouldThrowIfClaimsSetHasExpired() throws Exception {
        var expiredClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        expiredClaimsSetValues.put(
                JWTClaimNames.EXPIRATION_TIME,
                new Date(new Date().getTime() - 61000).getTime() / 1000);
        var expiredQueryParams =
                getValidQueryParams(generateClientAssertion(expiredClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () -> validator.authenticateClient(queryMapToString(expiredQueryParams)));

        assertTrue(exception.getMessage().contains("Expired JWT"));
    }

    @Test
    void shouldFailWhenClientJWTContainsExpiryClaimTooFarInFuture() throws Exception {
        when(mockOAuthKeyService.getClientSigningKey(any(), any()))
                .thenReturn(ECKey.parse(TEST_EC_PUBLIC_JWK));
        when(mockConfigService.getMaxAllowedAuthClientTtl()).thenReturn(2400L);
        var expiredClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        expiredClaimsSetValues.put(
                JWTClaimNames.EXPIRATION_TIME,
                new Date(new Date().getTime() + 9999999).getTime() / 1000);
        var expiredQueryParams =
                getValidQueryParams(generateClientAssertion(expiredClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () -> validator.authenticateClient(queryMapToString(expiredQueryParams)));
        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "The client JWT expiry date has surpassed the maximum allowed ttl value"));
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void shouldThrowIfMissingClientAssertionParam() {
        var queryParamsWithNoClientAssertion = new HashMap<>(getValidQueryParams("to be dropped"));
        queryParamsWithNoClientAssertion.remove("client_assertion");
        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(queryParamsWithNoClientAssertion)));

        assertEquals("Missing client_assertion parameter", exception.getCause().getMessage());
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void shouldThrowIfMissingClientAssertionTypeParam() {
        var queryParamsWithNoClientAssertionType =
                new HashMap<>(getValidQueryParams("to be dropped"));
        queryParamsWithNoClientAssertionType.remove("client_assertion_type");
        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(queryParamsWithNoClientAssertionType)));

        assertEquals("Missing client_assertion_type parameter", exception.getCause().getMessage());
    }

    @Test
    void shouldThrowIfJwtIdIsMissingOrEmpty() throws Exception {
        when(mockOAuthKeyService.getClientSigningKey(any(), any()))
                .thenReturn(ECKey.parse(TEST_EC_PUBLIC_JWK));
        when(mockConfigService.getMaxAllowedAuthClientTtl()).thenReturn(2400L);
        Map<String, Object> claimsSetValues = getClaimsSetValuesMissingJwtId();
        String clientAssertion = generateClientAssertion(claimsSetValues);

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(getValidQueryParams(clientAssertion))));

        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "InvalidClientException: The client auth JWT id (jti) is missing."));

        verify(mockClientAuthJwtIdService, Mockito.times(0)).getClientAuthJwtIdItem(anyString());
        verify(mockClientAuthJwtIdService, Mockito.times(0)).persistClientAuthJwtId(anyString());
    }

    @Test
    void shouldThrowIfJwtIdHasAlreadyBeenUsed() throws Exception {
        when(mockOAuthKeyService.getClientSigningKey(any(), any()))
                .thenReturn(ECKey.parse(TEST_EC_PUBLIC_JWK));
        when(mockConfigService.getMaxAllowedAuthClientTtl()).thenReturn(2400L);
        Map<String, Object> claimsSetValues = getValidClaimsSetValues();
        String clientAssertion = generateClientAssertion(claimsSetValues);

        ClientAuthJwtIdItem clientAuthJwtIdItem =
                new ClientAuthJwtIdItem(TEST_JTI, Instant.now().toString());
        when(mockClientAuthJwtIdService.getClientAuthJwtIdItem(TEST_JTI))
                .thenReturn(clientAuthJwtIdItem);

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(getValidQueryParams(clientAssertion))));

        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "InvalidClientException: The client auth JWT id (jti) has already been used."));
        verify(mockClientAuthJwtIdService, Mockito.times(0)).persistClientAuthJwtId(anyString());
    }

    private ECPrivateKey getEcPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        java.util.Base64.getDecoder()
                                                .decode(TestFixtures.EC_PRIVATE_KEY)));
    }

    private Map<String, String> getValidQueryParams(String clientAssertion) {
        return Map.of(
                "client_assertion", clientAssertion,
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "code", ResponseType.Value.CODE.getValue(),
                "grant_type", "authorization_code",
                "redirect_uri", "https://test-client.example.com/callback");
    }

    private String queryMapToString(Map<String, String> queryParams) {
        StringBuilder sb = new StringBuilder();

        for (Map.Entry<String, String> param : queryParams.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(
                    String.format(
                            "%s=%s",
                            URLEncoder.encode(param.getKey(), StandardCharsets.UTF_8),
                            URLEncoder.encode(param.getValue(), StandardCharsets.UTF_8)));
        }
        return sb.toString();
    }

    private Map<String, Object> getValidClaimsSetValues() {
        // Use the same audience the validator will check
        String expectedAud = mockConfigService.getComponentId();

        return Map.of(
                JWTClaimNames.ISSUER, CLIENT_ID,
                JWTClaimNames.SUBJECT, CLIENT_ID,
                JWTClaimNames.AUDIENCE, expectedAud,
                JWTClaimNames.EXPIRATION_TIME, fifteenMinutesFromNow(),
                JWTClaimNames.JWT_ID, TEST_JTI);
    }

    private Map<String, Object> getClaimsSetValuesMissingJwtId() {
        String expectedAud = mockConfigService.getComponentId();

        return Map.of(
                JWTClaimNames.ISSUER, CLIENT_ID,
                JWTClaimNames.SUBJECT, CLIENT_ID,
                JWTClaimNames.AUDIENCE, expectedAud,
                JWTClaimNames.EXPIRATION_TIME, fifteenMinutesFromNow());
    }

    private static long fifteenMinutesFromNow() {
        return OffsetDateTime.now().plusSeconds(15 * 60).toEpochSecond();
    }

    private String generateClientAssertion(Map<String, Object> claimsSetValues)
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        ECDSASigner signer = new ECDSASigner(getEcPrivateKey());

        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        generateClaimsSet(claimsSetValues));
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private JWTClaimsSet generateClaimsSet(Map<String, Object> claimsSetValues) {
        return new JWTClaimsSet.Builder()
                .claim(JWTClaimNames.ISSUER, claimsSetValues.get(JWTClaimNames.ISSUER))
                .claim(JWTClaimNames.SUBJECT, claimsSetValues.get(JWTClaimNames.SUBJECT))
                .claim(JWTClaimNames.AUDIENCE, claimsSetValues.get(JWTClaimNames.AUDIENCE))
                .claim(
                        JWTClaimNames.EXPIRATION_TIME,
                        claimsSetValues.get(JWTClaimNames.EXPIRATION_TIME))
                .claim(JWTClaimNames.JWT_ID, claimsSetValues.get(JWTClaimNames.JWT_ID))
                .build();
    }
}
