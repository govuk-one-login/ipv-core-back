package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK_2;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialJwtValidatorTest {

    public static final String AUDIENCE = "https://example.com/audience";
    public static final String ISSUER = "https://example.com/issuer";
    public static final String SUBJECT = "https://example.com/subject";

    private final ECDSASigner signer = getSigner();

    @Mock CredentialIssuerConfig credentialIssuerConfig;

    public VerifiableCredentialJwtValidatorTest() throws Exception {}

    @Test
    void doesNotThrowIfValidJwt() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn(ISSUER);

        SignedJWT signedJWT = getValidSignedJwt();

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        assertDoesNotThrow(() -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
    }

    @Test
    void shouldHandleDerEncodedSignatures() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn(ISSUER);

        SignedJWT signedJWT = getValidSignedJwt();
        Base64URL derSignature =
                Base64URL.encode(ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode()));
        SignedJWT derSignedJwt =
                new SignedJWT(
                        signedJWT.getHeader().toBase64URL(),
                        signedJWT.getPayload().toBase64URL(),
                        derSignature);

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        assertDoesNotThrow(() -> validator.validate(derSignedJwt, credentialIssuerConfig, SUBJECT));
    }

    @Test
    void throwsIfSignatureIsInvalid() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_2));

        SignedJWT signedJWT = getValidSignedJwt();

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsIfCanNotParseVerifyingPublicKey() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenThrow(new ParseException("Nope", 0));

        SignedJWT signedJWT = getValidSignedJwt();

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_JWK, exception.getErrorResponse());
    }

    @Test
    void throwsIfIssuerDoesNotMatch() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn("THIS IS WRONG");

        SignedJWT signedJWT = getValidSignedJwt();

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsIfAudienceDoesNotMatch() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn(ISSUER);

        SignedJWT signedJWT = getValidSignedJwt();

        VerifiableCredentialJwtValidator validator =
                new VerifiableCredentialJwtValidator("THIS IS THE WRONG AUDIENCE");

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsIfSubjectDoesNotMatch() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn(ISSUER);

        SignedJWT signedJWT = getValidSignedJwt();

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                validator.validate(
                                        signedJWT,
                                        credentialIssuerConfig,
                                        "THIS IS THE WRONG SUBJECT"));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsIfExpired() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn(ISSUER);

        Instant now = Instant.now();
        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        new JWTClaimsSet.Builder()
                                .issuer(ISSUER)
                                .subject(SUBJECT)
                                .audience(AUDIENCE)
                                .expirationTime(new Date(now.minusSeconds(60).toEpochMilli()))
                                .notBeforeTime(new Date(now.toEpochMilli()))
                                .claim("vc", new Object())
                                .build());

        signedJWT.sign(signer);

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsIfNotBeforeIsInTheFuture() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn(ISSUER);

        Instant now = Instant.now();
        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        new JWTClaimsSet.Builder()
                                .issuer(ISSUER)
                                .subject(SUBJECT)
                                .audience(AUDIENCE)
                                .expirationTime(new Date(now.plusSeconds(60).toEpochMilli()))
                                .notBeforeTime(new Date(now.plusSeconds(100).toEpochMilli()))
                                .claim("vc", new Object())
                                .build());

        signedJWT.sign(signer);

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsIfVcClaimIsMissing() throws Exception {
        when(credentialIssuerConfig.getVcVerifyingPublicJwk())
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK));
        when(credentialIssuerConfig.getAudienceForClients()).thenReturn(ISSUER);

        Instant now = Instant.now();
        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        new JWTClaimsSet.Builder()
                                .issuer(ISSUER)
                                .subject(SUBJECT)
                                .audience(AUDIENCE)
                                .expirationTime(new Date(now.plusSeconds(60).toEpochMilli()))
                                .notBeforeTime(new Date(now.toEpochMilli()))
                                .build());

        signedJWT.sign(signer);

        VerifiableCredentialJwtValidator validator = new VerifiableCredentialJwtValidator(AUDIENCE);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () -> validator.validate(signedJWT, credentialIssuerConfig, SUBJECT));
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    private ECDSASigner getSigner() throws Exception {
        return new ECDSASigner(
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY))),
                Curve.P_256);
    }

    private SignedJWT getValidSignedJwt() throws Exception {
        Instant now = Instant.now();
        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        new JWTClaimsSet.Builder()
                                .issuer(ISSUER)
                                .subject(SUBJECT)
                                .audience(AUDIENCE)
                                .expirationTime(new Date(now.plusSeconds(60).toEpochMilli()))
                                .notBeforeTime(new Date(now.toEpochMilli()))
                                .claim("vc", new Object())
                                .build());

        signedJWT.sign(signer);
        return signedJWT;
    }
}
