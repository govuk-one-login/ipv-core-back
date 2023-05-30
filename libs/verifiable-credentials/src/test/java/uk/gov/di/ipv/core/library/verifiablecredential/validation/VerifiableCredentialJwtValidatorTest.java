package uk.gov.di.ipv.core.library.verifiablecredential.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.verifiablecredential.exception.VerifiableCredentialException;

import java.text.ParseException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.vcClaim;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialJwtValidatorTest {
    private static final String TEST_USER = "urn:uuid:596f44ec-5c53-4965-9ef4-e8200e39cf35";
    private static final String TEST_ISSUER =
            "https://staging-di-ipv-cri-address-front.london.cloudapps.digital";
    private static final ECKey TEST_SIGNING_KEY;
    private static final ECKey TEST_SIGNING_KEY2;

    static {
        try {
            TEST_SIGNING_KEY = ECKey.parse(EC_PRIVATE_KEY_JWK);
            TEST_SIGNING_KEY2 =
                    ECKey.parse(
                            "{\"crv\":\"P-256\",\"d\":\"o1orSH_mS3u1zzi4wXa9C-cgY2bPyZWN5DxK78JCN6E\",\"kty\":\"EC\",\"x\":\"LziA3lV476BwPG5glvLLx8-FzMbeX2ti9wYlhwCWNhQ\",\"y\":\"NfvgSlu1TMNjjMRM3um29Tv79C4NL8x6WEY7t4BBneA\"}");
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Mock private CredentialIssuerConfig credentialIssuerConfig;
    private SignedJWT verifiableCredentials;

    private final VerifiableCredentialJwtValidator vcJwtValidator =
            new VerifiableCredentialJwtValidator();

    @BeforeEach
    void setUp() throws Exception {
        verifiableCredentials = createTestVerifiableCredentials(TEST_USER, TEST_ISSUER);
    }

    @Test
    void validatesValidVerifiableCredentialsSuccessfully() {
        setCredentialIssuerConfigMockResponses(TEST_SIGNING_KEY);
        vcJwtValidator.validate(verifiableCredentials, credentialIssuerConfig, TEST_USER);
    }

    @Test
    void validateThrowsErrorOnInvalidVerifiableCredentials() {
        setCredentialIssuerConfigMockResponses(TEST_SIGNING_KEY);
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.validate(
                                    verifiableCredentials,
                                    credentialIssuerConfig,
                                    "a different user");
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void validateThrowsErrorOnInvalidVerifiableCredentialsSignature() {
        try {
            when(credentialIssuerConfig.getSigningKey()).thenReturn(TEST_SIGNING_KEY2);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.validate(
                                    verifiableCredentials, credentialIssuerConfig, TEST_USER);
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void validatesValidVerifiableCredentialsWithDerSignatureSuccessfully()
            throws JOSEException, ParseException {
        setCredentialIssuerConfigMockResponses(TEST_SIGNING_KEY);
        var jwtParts = verifiableCredentials.getParsedParts();
        var verifiableCredentialsWithDerSignature =
                new SignedJWT(
                        jwtParts[0],
                        jwtParts[1],
                        Base64URL.encode(
                                ECDSA.transcodeSignatureToDER(
                                        verifiableCredentials.getSignature().decode())));
        vcJwtValidator.validate(
                verifiableCredentialsWithDerSignature, credentialIssuerConfig, TEST_USER);
    }

    @Test
    void throwsErrorOnVerifiableCredentialsWithInvalidDerSignature()
            throws JOSEException, ParseException {
        var derSignature =
                ECDSA.transcodeSignatureToDER(verifiableCredentials.getSignature().decode());
        var jwtParts = verifiableCredentials.getParsedParts();
        var verifiableCredentialsWithDerSignature =
                new SignedJWT(
                        jwtParts[0],
                        jwtParts[1],
                        Base64URL.encode(
                                Arrays.copyOfRange(derSignature, 1, derSignature.length - 2)));
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.validate(
                                    verifiableCredentialsWithDerSignature,
                                    credentialIssuerConfig,
                                    TEST_USER);
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    private void setCredentialIssuerConfigMockResponses(ECKey signingKey) {
        when(credentialIssuerConfig.getComponentId())
                .thenReturn("https://staging-di-ipv-cri-address-front.london.cloudapps.digital");
        try {
            when(credentialIssuerConfig.getSigningKey()).thenReturn(signingKey);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private SignedJWT createTestVerifiableCredentials(String subject, String issuer)
            throws Exception {
        return SignedJWT.parse(
                generateVerifiableCredential(vcClaim(CREDENTIAL_ATTRIBUTES_2), subject, issuer));
    }

    /**
     * Base64URL transcodedSignatureBase64 = Base64URL.encode( ECDSA.transcodeSignatureToConcat(
     * vc.getSignature().decode(), ECDSA.getSignatureByteArrayLength(ES256)));
     *
     * <p>Base64URL transcodedSignatureBase64 = Base64URL.encode( ECDSA.transcodeSignatureToConcat(
     * vc.getSignature().decode(), ECDSA.getSignatureByteArrayLength(ES256)));
     *
     * <p>Base64URL[] jwtParts = vc.getParsedParts(); return new SignedJWT(jwtParts[0], jwtParts[1],
     * transcodedSignatureBase64);
     */
}
