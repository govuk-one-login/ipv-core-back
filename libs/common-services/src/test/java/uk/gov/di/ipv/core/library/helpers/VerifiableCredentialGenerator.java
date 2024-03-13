package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EncodedKeySpec;
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

public class VerifiableCredentialGenerator {
    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, Map<String, Object> vcClaim) throws Exception {
        return generateVerifiableCredential(userId, criId, vcClaim, "https://subject.example.com");
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, Map<String, Object> vcClaim, String issuer)
            throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(SUBJECT, userId)
                        .claim(ISSUER, issuer)
                        .claim(NOT_BEFORE, now.getEpochSecond())
                        .claim(VC_CLAIM, vcClaim)
                        .build();
        return signTestVc(userId, criId, claimsSet);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, TestVc vcClaim, String issuer, Instant nbf) {
        try {
            JWTClaimsSet claimsSet =
                    new JWTClaimsSet.Builder()
                            .claim(SUBJECT, userId)
                            .claim(ISSUER, issuer)
                            .claim(NOT_BEFORE, nbf.getEpochSecond())
                            .claim(VC_CLAIM, vcClaim)
                            .build();
            return signTestVc(userId, criId, claimsSet);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, TestVc vcClaim) {
        try {
            return generateVerifiableCredential(userId, criId, vcClaim, null, Instant.now());
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
        return signTestVc(userId, criId, claimsSet);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, String criId, TestVc vcClaim, Instant nbf) {
        try {
            JWTClaimsSet claimsSet =
                    new JWTClaimsSet.Builder()
                            .claim(SUBJECT, userId)
                            .claim(ISSUER, "https://review-p.staging.account.gov.uk")
                            .claim(NOT_BEFORE, nbf.getEpochSecond())
                            .claim(VC_CLAIM, vcClaim)
                            .build();
            return signTestVc(userId, criId, claimsSet);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // TODO: PYIC-5171 Replace this method
    private static VerifiableCredential signTestVc(
            String userId, String criId, JWTClaimsSet claimsSet) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec privateKeySpec =
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(EC_PRIVATE_KEY));
        ECDSASigner ecdsaSigner =
                new ECDSASigner((ECPrivateKey) kf.generatePrivate(privateKeySpec));

        JWSHeader jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(ecdsaSigner);

        // Parsing and serialising here allows us to cast like before.
        // The casting will be replaced in PYIC-5171 and so should this.
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
