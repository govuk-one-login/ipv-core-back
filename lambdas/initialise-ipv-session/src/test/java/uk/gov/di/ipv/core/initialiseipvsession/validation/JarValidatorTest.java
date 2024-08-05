package uk.gov.di.ipv.core.initialiseipvsession.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarClaims;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarUserInfo;
import uk.gov.di.ipv.core.initialiseipvsession.domain.StringListClaim;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_FORBIDDEN;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CLIENT_ISSUER;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CLIENT_VALID_REDIRECT_URLS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CLIENT_VALID_SCOPES;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.SCOPE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class JarValidatorTest {
    private static final String CLAIMS_CLAIM = "claims";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final long TWENTY_FIVE_MINUTES_IN_SECONDS = 1500L;

    @Mock private ConfigService configService;
    @Mock private JWEDecrypter jweDecrypter;
    private JarValidator jarValidator;

    private final String audienceClaim = "test-audience";
    private final String issuerClaim = "test-issuer";
    private final String subjectClaim = "test-subject";
    private final String responseTypeClaim = "code";
    private final String clientIdClaim = "test-client-id";
    private final String redirectUriClaim = "https://example.com";
    private final String stateClaim = "af0ifjsldkj";
    private final String scopeClaim = "test-scope";

    @BeforeEach
    void setUp() {
        jarValidator = new JarValidator(jweDecrypter, configService);
    }

    @Test
    void decryptJWEShouldReturnSignedJwtOnSuccessfulDecryption() throws Exception {
        SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());
        when(jweDecrypter.decrypt(any(), any(), any(), any(), any(), any()))
                .thenReturn(signedJWT.serialize().getBytes(StandardCharsets.UTF_8));

        String jweObjectString =
                "eyJ0eXAiOiJKV0UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.ZpVOfw61XyBBgsR4CRNRMn2oj_S65pMJO-iaEHpR6QrPcIuD4ysZexolo28vsZyZNR-kfVdw_5CjQanwMS-yw3U3nSUvXUrTs3uco-FSXulIeDYTRbBtQuDyvBMVoos6DyIfC6eBj30GMe5g6DF5KJ1Q0eXQdF0kyM9olg76uYAUqZ5rW52rC_SOHb5_tMj7UbO2IViIStdzLgVfgnJr7Ms4bvG0C8-mk4Otd7m2Km2-DNyGaNuFQSKclAGu7Zgg-qDyhH4V1Z6WUHt79TuG4TxseUr-6oaFFVD23JYSBy7Aypt0321ycq13qcN-PBiOWtumeW5-_CQuHLaPuOc4-w.RO9IB2KcS2hD3dWlKXSreQ.93Ntu3e0vNSYv4hoMwZ3Aw.YRvWo4bwsP_l7dL_29imGg";

        SignedJWT decryptedJwt = jarValidator.decryptJWE(JWEObject.parse(jweObjectString));

        JWTClaimsSet claimsSet = decryptedJwt.getJWTClaimsSet();
        assertEquals(redirectUriClaim, claimsSet.getStringClaim("redirect_uri"));
        assertEquals(Collections.singletonList(audienceClaim), claimsSet.getAudience());
        assertEquals(subjectClaim, claimsSet.getSubject());
    }

    @Test
    void decryptJWEShouldThrowExceptionIfDecryptionFails() {
        String jweObjectString =
                "eyJ0eXAiOiJKV0UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.ZpVOfw61XyBBgsR4CRNRMn2oj_S65pMJO-iaEHpR6QrPcIuD4ysZexolo28vsZyZNR-kfVdw_5CjQanwMS-yw3U3nSUvXUrTs3uco-FSXulIeDYTRbBtQuDyvBMVoos6DyIfC6eBj30GMe5g6DF5KJ1Q0eXQdF0kyM9olg76uYAUqZ5rW52rC_SOHb5_tMj7UbO2IViIStdzLgVfgnJr7Ms4bvG0C8-mk4Otd7m2Km2-DNyGaNuFQSKclAGu7Zgg-qDyhH4V1Z6WUHt79TuG4TxseUr-6oaFFVD23JYSBy7Aypt0321ycq13qcN-PBiOWtumeW5-_CQuHLaPuOc4-w.RO9IB2KcS2hD3dWlKXSreQ.93Ntu3e0vNSYv4hoMwZ3Aw.YRvWo4bwsP_l7dL_29imGg";

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.decryptJWE(JWEObject.parse(jweObjectString)));
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), thrown.getErrorObject().getCode());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void validateRequestJwtShouldPassValidationChecksOnValidJARRequest(boolean mfaResetEnabled)
            throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));
        when(configService.enabled(MFA_RESET)).thenReturn(mfaResetEnabled);
        if (mfaResetEnabled) {
            when(configService.getParameter(CLIENT_VALID_SCOPES, clientIdClaim))
                    .thenReturn("openid");
        }

        SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

        assertDoesNotThrow(() -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnInvalidClientId() throws Exception {
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                .thenThrow(ConfigParameterNotFoundException.class);

        SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_CLIENT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorObject.getCode());
        assertEquals("Unknown client id was provided", errorObject.getDescription());
    }

    @Nested
    class ScopeTests {
        @BeforeEach
        public void setUp() {
            when(configService.enabled(MFA_RESET)).thenReturn(true);
        }

        @Test
        void validateRequestJwtShouldThrowRecoverableExceptionIfScopeClaimMissing()
                throws Exception {
            when(configService.getParameter(
                            eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                    .thenReturn(TEST_EC_PUBLIC_JWK);
            when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
            when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                    .thenReturn(issuerClaim);
            when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                    .thenReturn(Collections.singletonList(redirectUriClaim));

            var claimsSetValues = getValidClaimsSetValues();
            claimsSetValues.remove("scope");
            SignedJWT signedJWT = generateJWT(claimsSetValues);

            RecoverableJarValidationException thrown =
                    assertThrows(
                            RecoverableJarValidationException.class,
                            () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
            ErrorObject errorObject = thrown.getErrorObject();
            assertEquals(
                    OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
            assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
            assertEquals("Claim set validation failed", errorObject.getDescription());
        }

        @Test
        void validateRequestJwtShouldPassIfNoRequiredScopeProvided() throws Exception {
            when(configService.getParameter(
                            eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                    .thenReturn(TEST_EC_PUBLIC_JWK);
            when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
            when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                    .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
            when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                    .thenReturn(issuerClaim);
            when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                    .thenReturn(Collections.singletonList(redirectUriClaim));

            var claimsSetValues = getValidClaimsSetValues();
            claimsSetValues.put("scope", "no required scope");
            SignedJWT signedJWT = generateJWT(claimsSetValues);

            assertDoesNotThrow(() -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        }

        @Test
        void validateRequestJwtShouldFailValidationChecksOnInvalidScopeForClient()
                throws Exception {
            when(configService.getParameter(
                            eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                    .thenReturn(TEST_EC_PUBLIC_JWK);
            when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                    .thenReturn(issuerClaim);
            when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
            when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                    .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
            when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                    .thenReturn(Collections.singletonList(redirectUriClaim));
            when(configService.getParameter(CLIENT_VALID_SCOPES, clientIdClaim))
                    .thenReturn("reverification");

            SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

            JarValidationException thrown =
                    assertThrows(
                            JarValidationException.class,
                            () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
            ErrorObject errorObject = thrown.getErrorObject();
            assertEquals(SC_FORBIDDEN, errorObject.getHTTPStatusCode());
            assertEquals(OAuth2Error.INVALID_SCOPE.getCode(), errorObject.getCode());
            assertEquals(
                    "Client not allowed to issue a request with this scope",
                    errorObject.getDescription());
        }

        @Test
        void validateRequestJwtShouldFailValidationChecksIfOpenIdAndReverificationScopesProvided()
                throws Exception {
            when(configService.getParameter(
                            eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                    .thenReturn(TEST_EC_PUBLIC_JWK);
            when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
            when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                    .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
            when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                    .thenReturn(issuerClaim);
            when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                    .thenReturn(Collections.singletonList(redirectUriClaim));

            var claimsSetValues = getValidClaimsSetValues();
            claimsSetValues.put("scope", "openid reverification");
            SignedJWT signedJWT = generateJWT(claimsSetValues);

            JarValidationException thrown =
                    assertThrows(
                            JarValidationException.class,
                            () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
            ErrorObject errorObject = thrown.getErrorObject();
            assertEquals(SC_FORBIDDEN, errorObject.getHTTPStatusCode());
            assertEquals(OAuth2Error.INVALID_SCOPE.getCode(), errorObject.getCode());
            assertEquals(
                    "Client not allowed to issue a request with this scope",
                    errorObject.getDescription());
        }

        @Test
        void validateRequestJwtShouldFailValidationChecksOnEmptyValidScopesForClient()
                throws Exception {
            when(configService.getParameter(
                            eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                    .thenReturn(TEST_EC_PUBLIC_JWK);
            when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
            when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                    .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
            when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                    .thenReturn(issuerClaim);
            when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                    .thenReturn(Collections.singletonList(redirectUriClaim));
            when(configService.getParameter(CLIENT_VALID_SCOPES, clientIdClaim)).thenReturn("");

            SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

            JarValidationException thrown =
                    assertThrows(
                            JarValidationException.class,
                            () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
            ErrorObject errorObject = thrown.getErrorObject();
            assertEquals(SC_FORBIDDEN, errorObject.getHTTPStatusCode());
            assertEquals(OAuth2Error.INVALID_SCOPE.getCode(), errorObject.getCode());
            assertEquals(
                    "Client not allowed to issue a request with this scope",
                    errorObject.getDescription());
        }

        @Test
        void validateRequestJwtShouldFailValidationChecksOnScopeNotDefinedForClient()
                throws Exception {
            when(configService.getParameter(
                            eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                    .thenReturn(TEST_EC_PUBLIC_JWK);
            when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
            when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                    .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
            when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                    .thenReturn(issuerClaim);
            when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                    .thenReturn(Collections.singletonList(redirectUriClaim));
            when(configService.getParameter(CLIENT_VALID_SCOPES, clientIdClaim))
                    .thenThrow(ConfigParameterNotFoundException.class);

            SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

            JarValidationException thrown =
                    assertThrows(
                            JarValidationException.class,
                            () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
            ErrorObject errorObject = thrown.getErrorObject();
            assertEquals(
                    OAuth2Error.INVALID_CLIENT.getHTTPStatusCode(),
                    errorObject.getHTTPStatusCode());
            assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorObject.getCode());
            assertEquals("Allowed scopes not found for client", errorObject.getDescription());
        }

        @Test
        void validateRequestJwtShouldFailValidationCheckIfScopeCanNotBeParsed() throws Exception {
            when(configService.getParameter(
                            eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                    .thenReturn(TEST_EC_PUBLIC_JWK);
            when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
            when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                    .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
            when(configService.getParameter(eq(CLIENT_ISSUER), anyString()))
                    .thenReturn(issuerClaim);
            when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                    .thenReturn(Collections.singletonList(redirectUriClaim));

            var claimsSetValues = getValidClaimsSetValues();
            claimsSetValues.put(SCOPE, 1);
            SignedJWT signedJWT = generateJWT(claimsSetValues);

            JarValidationException thrown =
                    assertThrows(
                            JarValidationException.class,
                            () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
            ErrorObject errorObject = thrown.getErrorObject();
            assertEquals(
                    OAuth2Error.INVALID_SCOPE.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
            assertEquals(OAuth2Error.INVALID_SCOPE.getCode(), errorObject.getCode());
            assertEquals("Scope could not be parsed", errorObject.getDescription());
        }
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnValidJWTalgHeader() throws Exception {

        RSASSASigner signer = new RSASSASigner(getRsaPrivateKey());

        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                        generateClaimsSet(getValidClaimsSetValues()));
        signedJWT.sign(signer);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode(),
                errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorObject.getCode());
        assertEquals(
                "Signing algorithm used does not match required algorithm",
                errorObject.getDescription());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnInvalidJWTSignature() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(EC_PUBLIC_JWK_2);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);

        SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode(),
                errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorObject.getCode());
        assertEquals("JWT signature validation failed", errorObject.getDescription());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnInvalidPublicJwk() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn("invalid-jwk");
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode(),
                errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorObject.getCode());
        assertEquals(
                "Failed to parse JWT when attempting signature validation",
                errorObject.getDescription());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnMissingRequiredClaim()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        ECDSASigner signer = new ECDSASigner(getPrivateKey());

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder().claim(JWTClaimNames.AUDIENCE, audienceClaim).build();

        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        claimsSet);
        signedJWT.sign(signer);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "Invalid redirect_uri claim provided for configured client",
                errorObject.getDescription());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnInvalidAudienceClaim() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        Map<String, Object> invalidAudienceClaims = getValidClaimsSetValues();
        invalidAudienceClaims.put(JWTClaimNames.AUDIENCE, "invalid-audience");

        SignedJWT signedJWT = generateJWT(invalidAudienceClaims);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "JWT audience rejected: [invalid-audience]",
                thrown.getCause().getCause().getMessage());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnInvalidIssuerClaim() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        Map<String, Object> invalidIssuerClaims = getValidClaimsSetValues();
        invalidIssuerClaims.put(JWTClaimNames.ISSUER, "invalid-issuer");

        SignedJWT signedJWT = generateJWT(invalidIssuerClaims);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "JWT iss claim has value invalid-issuer, must be test-issuer",
                thrown.getCause().getCause().getMessage());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnInvalidResponseTypeClaim() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        Map<String, Object> invalidResponseTypeClaim = getValidClaimsSetValues();
        invalidResponseTypeClaim.put("response_type", "invalid-response-type");

        SignedJWT signedJWT = generateJWT(invalidResponseTypeClaim);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "JWT response_type claim has value invalid-response-type, must be code",
                thrown.getCause().getCause().getMessage());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksIfClientIdClaimDoesNotMatchParam()
            throws Exception {
        var differentClientId = "different-client-id";
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, differentClientId))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, differentClientId));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "JWT client_id claim has value test-client-id, must be different-client-id",
                thrown.getCause().getCause().getMessage());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnExpiredJWT() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        Map<String, Object> expiredClaims = getValidClaimsSetValues();
        expiredClaims.put(JWTClaimNames.EXPIRATION_TIME, fifteenMinutesInPast());

        SignedJWT signedJWT = generateJWT(expiredClaims);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals("Expired JWT", thrown.getCause().getCause().getMessage());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnFutureNbfClaim() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        Map<String, Object> notValidYet = getValidClaimsSetValues();
        notValidYet.put(JWTClaimNames.NOT_BEFORE, fifteenMinutesFromNow());

        SignedJWT signedJWT = generateJWT(notValidYet);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals("JWT before use time", thrown.getCause().getCause().getMessage());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnExpiryClaimToFarInFuture() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(audienceClaim);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn(TWENTY_FIVE_MINUTES_IN_SECONDS);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList(redirectUriClaim));

        Map<String, Object> futureClaims = getValidClaimsSetValues();
        futureClaims.put(
                JWTClaimNames.EXPIRATION_TIME, OffsetDateTime.now().plusYears(100).toEpochSecond());

        SignedJWT signedJWT = generateJWT(futureClaims);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "The client JWT expiry date has surpassed the maximum allowed ttl value",
                errorObject.getDescription());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnInvalidRedirectUriClaim() throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);
        when(configService.getStringListParameter(CLIENT_VALID_REDIRECT_URLS, clientIdClaim))
                .thenReturn(Collections.singletonList("test-redirect-uri"));

        SignedJWT signedJWT = generateJWT(getValidClaimsSetValues());

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_GRANT.getHTTPStatusCode(), errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorObject.getCode());
        assertEquals(
                "Invalid redirect_uri claim provided for configured client",
                errorObject.getDescription());
    }

    @Test
    void validateRequestJwtShouldFailValidationChecksOnParseFailureOfRedirectUri()
            throws Exception {
        when(configService.getParameter(eq(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY), anyString()))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(configService.getParameter(eq(CLIENT_ISSUER), anyString())).thenReturn(issuerClaim);

        Map<String, Object> badRedirectClaims = getValidClaimsSetValues();
        badRedirectClaims.put("redirect_uri", "({[]})./sd-234345////invalid-redirect-uri");

        SignedJWT signedJWT = generateJWT(badRedirectClaims);

        JarValidationException thrown =
                assertThrows(
                        JarValidationException.class,
                        () -> jarValidator.validateRequestJwt(signedJWT, clientIdClaim));
        ErrorObject errorObject = thrown.getErrorObject();
        assertEquals(
                OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode(),
                errorObject.getHTTPStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST_OBJECT.getCode(), errorObject.getCode());
        assertEquals(
                "Failed to parse JWT claim set in order to access redirect_uri claim",
                errorObject.getDescription());
    }

    private SignedJWT generateJWT(Map<String, Object> claimsSetValues) throws Exception {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());

        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        generateClaimsSet(claimsSetValues));
        signedJWT.sign(signer);

        return signedJWT;
    }

    private Map<String, Object> getValidClaimsSetValues() {
        var validClaims = new HashMap<String, Object>();
        validClaims.put(JWTClaimNames.EXPIRATION_TIME, fifteenMinutesFromNow());
        validClaims.put(JWTClaimNames.ISSUED_AT, OffsetDateTime.now().toEpochSecond());
        validClaims.put(JWTClaimNames.NOT_BEFORE, OffsetDateTime.now().toEpochSecond());
        validClaims.put(JWTClaimNames.AUDIENCE, audienceClaim);
        validClaims.put(JWTClaimNames.ISSUER, issuerClaim);
        validClaims.put(JWTClaimNames.SUBJECT, subjectClaim);
        validClaims.put("scope", scopeClaim);
        validClaims.put("response_type", responseTypeClaim);
        validClaims.put("client_id", clientIdClaim);
        validClaims.put("redirect_uri", redirectUriClaim);
        validClaims.put("state", stateClaim);
        validClaims.put("scope", "openid phone email");
        validClaims.put(
                CLAIMS_CLAIM,
                new JarClaims(
                        new JarUserInfo(
                                null,
                                null,
                                new StringListClaim(List.of("DEFO.A.JWT")),
                                new StringListClaim(List.of("EVCS_ACCESS_TOKEN")),
                                null)));
        return validClaims;
    }

    private JWTClaimsSet generateClaimsSet(Map<String, Object> claimsSetValues) throws Exception {
        return JWTClaimsSet.parse(OBJECT_MAPPER.writeValueAsString(claimsSetValues));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }

    private RSAPrivateKey getRsaPrivateKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return (RSAPrivateKey)
                KeyFactory.getInstance("RSA")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(RSA_PRIVATE_KEY)));
    }

    private static long fifteenMinutesFromNow() {
        return Instant.now().plusSeconds(15 * 60).getEpochSecond();
    }

    private static long fifteenMinutesInPast() {
        return Instant.now().minusSeconds(15 * 60).getEpochSecond();
    }
}
