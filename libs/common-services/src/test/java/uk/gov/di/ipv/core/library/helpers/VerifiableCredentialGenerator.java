package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME;
import static com.nimbusds.jwt.JWTClaimNames.ISSUER;
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.DI_CONTEXT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CONTEXT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.W3_BASE_CONTEXT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;

public class VerifiableCredentialGenerator {
    public static String generateVerifiableCredential(Map<String, Object> vcClaim, String issuer)
            throws Exception {
        return generateVerifiableCredential(vcClaim, "https://subject.example.com", issuer);
    }

    public static String generateVerifiableCredential(
            Map<String, Object> vcClaim, String subject, String issuer) throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(SUBJECT, subject)
                        .claim(ISSUER, issuer)
                        .claim(NOT_BEFORE, now.getEpochSecond())
                        .claim(EXPIRATION_TIME, now.plusSeconds(600).getEpochSecond())
                        .claim(VC_CLAIM, vcClaim)
                        .build();
        return signTestJWT(claimsSet);
    }

    public static String generateVerifiableCredential(TestVc vcClaim, String subject, String issuer)
            throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(SUBJECT, subject)
                        .claim(ISSUER, issuer)
                        .claim(NOT_BEFORE, now.getEpochSecond())
                        .claim(VC_CLAIM, vcClaim)
                        .build();
        return signTestJWT(claimsSet);
    }

    public static String generateVerifiableCredential(
            TestVc vcClaim, String subject, String issuer, Instant nbf) throws Exception {
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(SUBJECT, subject)
                        .claim(ISSUER, issuer)
                        .claim(NOT_BEFORE, nbf.getEpochSecond())
                        .claim(EXPIRATION_TIME, nbf.plusSeconds(600).getEpochSecond())
                        .claim(VC_CLAIM, vcClaim)
                        .build();
        return signTestJWT(claimsSet);
    }

    private static String signTestJWT(JWTClaimsSet claimsSet) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec privateKeySpec =
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(EC_PRIVATE_KEY));
        ECDSASigner ecdsaSigner =
                new ECDSASigner((ECPrivateKey) kf.generatePrivate(privateKeySpec));

        JWSHeader jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(ecdsaSigner);

        return signedJWT.serialize();
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
