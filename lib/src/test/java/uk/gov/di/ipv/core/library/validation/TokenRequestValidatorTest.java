package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.core.library.persistence.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.library.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_PUBLIC_CERT;

@ExtendWith(MockitoExtension.class)
class TokenRequestValidatorTest {

    private TokenRequestValidator validator;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private ClientAuthJwtIdService mockClientAuthJwtIdService;

    private final String clientId = "di-ipv-orchestrator-stub";
    private final String audience =
            "https://ea8lfzcdq0.execute-api.eu-west-2.amazonaws.com/dev/token";
    private final String jti = "test-jti";

    @BeforeEach
    void setUp() {
        when(mockConfigurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(audience);
        validator = new TokenRequestValidator(mockConfigurationService, mockClientAuthJwtIdService);
    }

    @Test
    void shouldNotThrowForValidJwtSignedWithRS256()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        when(mockConfigurationService.getSsmParameter(
                        eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(RSA_PUBLIC_CERT);
        when(mockConfigurationService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn("2400");

        var validQueryParams =
                getValidQueryParams(generateClientAssertionWithRS256(getValidClaimsSetValues()));
        assertDoesNotThrow(() -> validator.authenticateClient(queryMapToString(validQueryParams)));
    }

    @Test
    void shouldNotThrowForValidJwtSignedWithES256()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        when(mockConfigurationService.getSsmParameter(
                        eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(EC_PUBLIC_JWK);
        when(mockConfigurationService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn("2400");

        var validQueryParams =
                getValidQueryParams(generateClientAssertionWithES256(getValidClaimsSetValues()));
        assertDoesNotThrow(() -> validator.authenticateClient(queryMapToString(validQueryParams)));
    }

    @Test
    void shouldThrowIfInvalidSignature() throws Exception {
        when(mockConfigurationService.getSsmParameter(
                        eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(RSA_PUBLIC_CERT);

        var invalidSignatureQueryParams =
                new HashMap<>(
                        getValidQueryParams(
                                generateClientAssertionWithRS256(getValidClaimsSetValues())));
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
                        generateClientAssertionWithRS256(differentIssuerAndSubjectClaimsSetValues));

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
                                "Issuer and subject in client JWT assertion must designate the same client identifier"));
    }

    @Test
    void shouldThrowIfWrongAudience()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        var wrongAudienceClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        wrongAudienceClaimsSetValues.put(
                JWTClaimNames.AUDIENCE, "NOT_THE_AUDIENCE_YOU_ARE_LOOKING_FOR");
        var wrongAudienceQueryParams =
                getValidQueryParams(generateClientAssertionWithRS256(wrongAudienceClaimsSetValues));

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
                                "Invalid JWT audience claim, expected [https://ea8lfzcdq0.execute-api.eu-west-2.amazonaws.com/dev/token]"));
    }

    @Test
    void shouldThrowIfClaimsSetHasExpired()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        var expiredClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        expiredClaimsSetValues.put(
                JWTClaimNames.EXPIRATION_TIME,
                new Date(new Date().getTime() - 61000).getTime() / 1000);
        var expiredQueryParams =
                getValidQueryParams(generateClientAssertionWithRS256(expiredClaimsSetValues));

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () -> validator.authenticateClient(queryMapToString(expiredQueryParams)));

        assertTrue(exception.getMessage().contains("Expired JWT"));
    }

    @Test
    void shouldFailWhenClientJWTContainsExpiryClaimTooFarInFuture()
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        when(mockConfigurationService.getSsmParameter(
                        eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(RSA_PUBLIC_CERT);
        when(mockConfigurationService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn("2400");
        var expiredClaimsSetValues = new HashMap<>(getValidClaimsSetValues());
        expiredClaimsSetValues.put(
                JWTClaimNames.EXPIRATION_TIME,
                new Date(new Date().getTime() + 9999999).getTime() / 1000);
        var expiredQueryParams =
                getValidQueryParams(generateClientAssertionWithRS256(expiredClaimsSetValues));

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
    void shouldCheckIfJwtIdIsMissingOrEmpty() throws Exception {
        when(mockConfigurationService.getSsmParameter(
                        eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(RSA_PUBLIC_CERT);
        when(mockConfigurationService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn("2400");
        Map<String, Object> claimsSetValues = getClaimsSetValuesMissingJwtId();
        String clientAssertion = generateClientAssertionWithRS256(claimsSetValues);

        validator.authenticateClient(queryMapToString(getValidQueryParams(clientAssertion)));

        verify(mockClientAuthJwtIdService, Mockito.times(0)).getClientAuthJwtIdItem(anyString());
    }

    @Test
    void shouldStoreJwtIdAndCheckItHasNotAlreadyBeenUsed() throws Exception {
        when(mockConfigurationService.getSsmParameter(
                        eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(RSA_PUBLIC_CERT);
        when(mockConfigurationService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn("2400");
        Map<String, Object> claimsSetValues = getValidClaimsSetValues();
        String clientAssertion = generateClientAssertionWithRS256(claimsSetValues);

        ClientAuthJwtIdItem clientAuthJwtIdItem =
                new ClientAuthJwtIdItem(jti, Instant.now().toString());
        when(mockClientAuthJwtIdService.getClientAuthJwtIdItem(jti))
                .thenReturn(clientAuthJwtIdItem);

        validator.authenticateClient(queryMapToString(getValidQueryParams(clientAssertion)));

        verify(mockClientAuthJwtIdService).getClientAuthJwtIdItem(jti);
    }

    private RSAPrivateKey getRsaPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (RSAPrivateKey)
                KeyFactory.getInstance("RSA")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        java.util.Base64.getDecoder().decode(RSA_PRIVATE_KEY)));
    }

    private ECPrivateKey getEcPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        java.util.Base64.getDecoder().decode(EC_PRIVATE_KEY)));
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
        return Map.of(
                JWTClaimNames.ISSUER,
                clientId,
                JWTClaimNames.SUBJECT,
                clientId,
                JWTClaimNames.AUDIENCE,
                audience,
                JWTClaimNames.EXPIRATION_TIME,
                fifteenMinutesFromNow(),
                JWTClaimNames.JWT_ID,
                jti);
    }

    private Map<String, Object> getClaimsSetValuesMissingJwtId() {
        return Map.of(
                JWTClaimNames.ISSUER,
                clientId,
                JWTClaimNames.SUBJECT,
                clientId,
                JWTClaimNames.AUDIENCE,
                audience,
                JWTClaimNames.EXPIRATION_TIME,
                fifteenMinutesFromNow());
    }

    private static long fifteenMinutesFromNow() {
        return OffsetDateTime.now().plusSeconds(15 * 60).toEpochSecond();
    }

    private String generateClientAssertionWithRS256(Map<String, Object> claimsSetValues)
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        RSASSASigner signer = new RSASSASigner(getRsaPrivateKey());

        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                        generateClaimsSet(claimsSetValues));
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private String generateClientAssertionWithES256(Map<String, Object> claimsSetValues)
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
