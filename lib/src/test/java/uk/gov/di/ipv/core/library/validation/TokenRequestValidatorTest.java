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
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CLIENT_AUTHENTICATION_METHOD;
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

    private final String clientId = "di-ipv-orchestrator-stub";
    private final String audience =
            "https://ea8lfzcdq0.execute-api.eu-west-2.amazonaws.com/dev/token";

    @BeforeEach
    void setUp() {
        when(mockConfigurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(audience);
        validator = new TokenRequestValidator(mockConfigurationService);
    }

    @Test
    void shouldNotThrowForValidJwtSignedWithRS256()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        when(mockConfigurationService.getSsmParameter(
                        eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(RSA_PUBLIC_CERT);
        when(mockConfigurationService.getSsmParameter(
                        eq(CLIENT_AUTHENTICATION_METHOD), anyString()))
                .thenReturn("jwt");
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
        when(mockConfigurationService.getSsmParameter(
                        eq(CLIENT_AUTHENTICATION_METHOD), anyString()))
                .thenReturn("jwt");
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
        when(mockConfigurationService.getSsmParameter(
                        eq(CLIENT_AUTHENTICATION_METHOD), anyString()))
                .thenReturn("jwt");

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
        when(mockConfigurationService.getSsmParameter(
                        eq(CLIENT_AUTHENTICATION_METHOD), anyString()))
                .thenReturn("jwt");
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
        when(mockConfigurationService.getSsmParameter(
                        eq(CLIENT_AUTHENTICATION_METHOD), anyString()))
                .thenReturn("jwt");
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
        when(mockConfigurationService.getSsmParameter(
                        eq(CLIENT_AUTHENTICATION_METHOD), anyString()))
                .thenReturn("jwt");
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
    void shouldNotThrowIfMissingClientAssertionParamWhenNoneRequired() {
        when(mockConfigurationService.getSsmParameter(CLIENT_AUTHENTICATION_METHOD, clientId))
                .thenReturn("none");
        var params = getValidQueryParamsWithoutClientAuth(clientId);

        assertDoesNotThrow(() -> validator.authenticateClient(queryMapToString(params)));
    }

    @Test
    void shouldNotThrowIfContainsClientAssertionParamWhenNoneRequired()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        when(mockConfigurationService.getSsmParameter(CLIENT_AUTHENTICATION_METHOD, clientId))
                .thenReturn("none");
        var validQueryParams =
                getValidQueryParams(generateClientAssertionWithRS256(getValidClaimsSetValues()));

        assertDoesNotThrow(() -> validator.authenticateClient(queryMapToString(validQueryParams)));
    }

    @Test
    void shouldThrowIfMissingClientAssertionParamWhenRequired() {
        String invalidClientId = "invalid-client";
        when(mockConfigurationService.getSsmParameter(
                        CLIENT_AUTHENTICATION_METHOD, invalidClientId))
                .thenReturn("jwt");
        var missingClientAssertionParams = getValidQueryParamsWithoutClientAuth(invalidClientId);

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(missingClientAssertionParams)));

        assertEquals(
                "Missing client_assertion jwt for configured client 'invalid-client'",
                exception.getMessage());
    }

    @Test
    void shouldThrowIfMissingClientAssertionAndClientIdParams() {
        var missingClientIdParams = getParamsWithoutClientAuthOrClientId();

        ClientAuthenticationException exception =
                assertThrows(
                        ClientAuthenticationException.class,
                        () ->
                                validator.authenticateClient(
                                        queryMapToString(missingClientIdParams)));

        assertEquals(
                "Unknown client, no client_id value or client_assertion jwt found in request",
                exception.getMessage());
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

    private Map<String, String> getValidQueryParamsWithoutClientAuth(String clientId) {
        return Map.of(
                "client_id",
                clientId,
                "code",
                ResponseType.Value.CODE.getValue(),
                "grant_type",
                "authorization_code",
                "redirect_uri",
                "https://test-client.example.com/callback");
    }

    private Map<String, String> getParamsWithoutClientAuthOrClientId() {
        return Map.of(
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
                .build();
    }
}
