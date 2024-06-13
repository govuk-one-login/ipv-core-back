package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.EncryptionAlgorithm;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.nimbusds.jwt.JWTClaimNames.ISSUER;
import static com.nimbusds.jwt.JWTClaimNames.JWT_ID;
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.DI_CONTEXT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CONTEXT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_VOT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_VTM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.W3_BASE_CONTEXT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_SIGNING_PRIVATE_JWK;

public class VerifiableCredentialGenerator {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, Map<String, Object> vcClaim) throws Exception {
        return generateVerifiableCredential(userId, criId, vcClaim, EncryptionAlgorithm.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            String criId,
            Map<String, Object> vcClaim,
            EncryptionAlgorithm encryptionAlgorithm)
            throws Exception {
        return generateVerifiableCredential(
                userId, criId, vcClaim, "https://subject.example.com", encryptionAlgorithm);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, Map<String, Object> vcClaim, String issuer)
            throws Exception {
        return generateVerifiableCredential(userId, criId, vcClaim, issuer, EncryptionAlgorithm.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            String criId,
            Map<String, Object> vcClaim,
            String issuer,
            EncryptionAlgorithm encryptionAlgorithm)
            throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(SUBJECT, userId)
                        .claim(ISSUER, issuer)
                        .claim(NOT_BEFORE, now.getEpochSecond())
                        .claim(VC_CLAIM, OBJECT_MAPPER.convertValue(vcClaim, Map.class))
                        .build();
        return signTestVc(userId, criId, claimsSet, encryptionAlgorithm);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, TestVc vcClaim, String issuer, Instant nbf) {
        return generateVerifiableCredential(
                userId, criId, vcClaim, issuer, nbf, EncryptionAlgorithm.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            String criId,
            TestVc vcClaim,
            String issuer,
            Instant nbf,
            EncryptionAlgorithm encryptionAlgorithm) {
        try {
            JWTClaimsSet claimsSet =
                    new JWTClaimsSet.Builder()
                            .claim(SUBJECT, userId)
                            .claim(ISSUER, issuer)
                            .claim(NOT_BEFORE, nbf.getEpochSecond())
                            .claim(VC_CLAIM, OBJECT_MAPPER.convertValue(vcClaim, Map.class))
                            .build();
            return signTestVc(userId, criId, claimsSet, encryptionAlgorithm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, TestVc vcClaim) {
        return generateVerifiableCredential(userId, criId, vcClaim, EncryptionAlgorithm.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, TestVc vcClaim, EncryptionAlgorithm encryptionAlgorithm) {
        try {
            return generateVerifiableCredential(
                    userId, criId, vcClaim, null, Instant.now(), encryptionAlgorithm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            String criId,
            TestVc vcClaim,
            String issuer,
            String vot,
            String jti,
            String vtm)
            throws Exception {
        return generateVerifiableCredential(
                userId, criId, vcClaim, issuer, vot, jti, vtm, EncryptionAlgorithm.EC);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            String criId,
            TestVc vcClaim,
            String issuer,
            String vot,
            String jti,
            String vtm,
            EncryptionAlgorithm encryptionAlgorithm)
            throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(SUBJECT, userId)
                        .claim(ISSUER, issuer)
                        .claim(NOT_BEFORE, now.getEpochSecond())
                        .claim(VC_CLAIM, vcClaim)
                        .claim(VC_VOT, vot)
                        .claim(JWT_ID, jti)
                        .claim(VC_VTM, vtm)
                        .build();
        return signTestVc(userId, criId, claimsSet, encryptionAlgorithm);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, TestVc vcClaim, Instant nbf) {
        return generateVerifiableCredential(userId, criId, vcClaim, nbf, EncryptionAlgorithm.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            String criId,
            TestVc vcClaim,
            Instant nbf,
            EncryptionAlgorithm signingAlgorithm) {
        try {
            JWTClaimsSet claimsSet =
                    new JWTClaimsSet.Builder()
                            .claim(SUBJECT, userId)
                            .claim(ISSUER, "https://review-p.staging.account.gov.uk")
                            .claim(NOT_BEFORE, nbf.getEpochSecond())
                            .claim(VC_CLAIM, vcClaim)
                            .build();
            return signTestVc(userId, criId, claimsSet, signingAlgorithm);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static VerifiableCredential signTestVc(
            String userId, String criId, JWTClaimsSet claimsSet, EncryptionAlgorithm algorithm)
            throws Exception {
        return switch (algorithm) {
            case EC -> signTestVcWithEc(userId, criId, claimsSet);
            case RSA -> signTestVcWithRSA(userId, criId, claimsSet);
        };
    }

    // TODO: PYIC-5171 Replace this method
    private static VerifiableCredential signTestVcWithEc(
            String userId, String criId, JWTClaimsSet claimsSet) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(EncryptionAlgorithm.EC.name());

        var privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(EC_PRIVATE_KEY));
        var signer = new ECDSASigner((ECPrivateKey) kf.generatePrivate(privateKeySpec));

        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet);

        signedJWT.sign(signer);

        // Parsing and serialising here allows us to cast like before.
        // The casting will be replaced in PYIC-5171 and so should this.
        return VerifiableCredential.fromValidJwt(
                userId, criId, SignedJWT.parse(signedJWT.serialize()));
    }

    // TODO: PYIC-5171 Same comments as for signTestVcWithEc
    private static VerifiableCredential signTestVcWithRSA(
            String userId, String criId, JWTClaimsSet claimsSet) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(EncryptionAlgorithm.RSA.name());

        var privateKeySpec =
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(RSA_SIGNING_PRIVATE_JWK));
        var signer = new RSASSASigner(kf.generatePrivate(privateKeySpec));

        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet);

        signedJWT.sign(signer);

        return VerifiableCredential.fromValidJwt(
                userId, criId, SignedJWT.parse(signedJWT.serialize()));
    }

    public static Map<String, Object> vcClaim(Map<String, Object> attributes) {
        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put(VC_CONTEXT, new String[] {W3_BASE_CONTEXT, DI_CONTEXT});
        vc.put(VC_TYPE, new String[] {VERIFIABLE_CREDENTIAL_TYPE, IDENTITY_CHECK_CREDENTIAL_TYPE});
        vc.put(VC_CREDENTIAL_SUBJECT, attributes);
        vc.put(
                VC_EVIDENCE,
                List.of(
                        Map.of(
                                "type",
                                "IdentityCheck",
                                "txn",
                                "DSJJSEE29392",
                                "verificationScore",
                                "0",
                                "ci",
                                List.of("A02", "A03"))));
        return vc;
    }
}
