package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.VerifiableCredentialType;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static com.nimbusds.jose.jwk.KeyType.EC;
import static com.nimbusds.jose.jwk.KeyType.RSA;
import static com.nimbusds.jwt.JWTClaimNames.ISSUED_AT;
import static com.nimbusds.jwt.JWTClaimNames.ISSUER;
import static com.nimbusds.jwt.JWTClaimNames.JWT_ID;
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.DI_CONTEXT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_VOT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_VTM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.W3_BASE_CONTEXT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_SIGNING_PRIVATE_KEY;

public class VerifiableCredentialGenerator {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            Cri cri,
            uk.gov.di.model.VerifiableCredential<?> vcClaim,
            String issuer) {
        return generateVerifiableCredential(
                userId, cri, vcClaim, issuer, Instant.now(), KeyType.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            Cri cri,
            uk.gov.di.model.VerifiableCredential<?> vcClaim,
            String issuer,
            Instant nbf) {
        return generateVerifiableCredential(userId, cri, vcClaim, issuer, nbf, KeyType.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            Cri cri,
            uk.gov.di.model.VerifiableCredential<?> vcClaim,
            String issuer,
            Instant nbf,
            KeyType signingKeyType) {
        return generateVerifiableCredential(
                userId, cri, vcClaim, issuer, nbf, null, null, null, signingKeyType);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId, Cri cri, uk.gov.di.model.VerifiableCredential<?> vcClaim) {
        return generateVerifiableCredential(userId, cri, vcClaim, null, Instant.now(), KeyType.EC);
    }

    public static VerifiableCredential generateVerifiableCredential(
            String userId,
            Cri cri,
            uk.gov.di.model.VerifiableCredential<?> vcClaim,
            String issuer,
            String vot,
            String jti,
            String vtm) {
        return generateVerifiableCredential(
                userId, cri, vcClaim, issuer, Instant.now(), vot, jti, vtm, KeyType.EC);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    private static VerifiableCredential generateVerifiableCredential(
            String userId,
            Cri cri,
            uk.gov.di.model.VerifiableCredential<?> vcClaim,
            String issuer,
            Instant nbf,
            String vot,
            String jti,
            String vtm,
            KeyType signingKeyType) {
        try {
            var claimSetBuilder =
                    new JWTClaimsSet.Builder()
                            .claim(SUBJECT, userId)
                            .claim(ISSUER, issuer)
                            .claim(VC_CLAIM, OBJECT_MAPPER.convertValue(vcClaim, Object.class));

            if (nbf != null) {
                claimSetBuilder
                        .claim(NOT_BEFORE, nbf.getEpochSecond())
                        .claim(ISSUED_AT, nbf.getEpochSecond());
            }

            if (vot != null) {
                claimSetBuilder.claim(VC_VOT, vot);
            }
            if (jti != null) {
                claimSetBuilder.claim(JWT_ID, jti);
            }
            if (vtm != null) {
                claimSetBuilder.claim(VC_VTM, vtm);
            }
            return signTestVc(userId, cri, claimSetBuilder.build(), signingKeyType);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static VerifiableCredential signTestVc(
            String userId, Cri cri, JWTClaimsSet claimsSet, KeyType signingKeyType)
            throws Exception {
        if (EC.equals(signingKeyType)) {
            return signTestVcWithEc(userId, cri, claimsSet);
        }

        if (RSA.equals(signingKeyType)) {
            return signTestVcWithRSA(userId, cri, claimsSet);
        }

        throw new RuntimeException("Signing key type is not EC or RSA");
    }

    // TODO: PYIC-5171 Replace this method
    // Same comments for signTestVcWithRSA
    private static VerifiableCredential signTestVcWithEc(
            String userId, Cri cri, JWTClaimsSet claimsSet) throws Exception {
        var kf = KeyFactory.getInstance(KeyType.EC.getValue());

        var privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(EC_PRIVATE_KEY));
        var signer = new ECDSASigner((ECPrivateKey) kf.generatePrivate(privateKeySpec));

        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet);

        signedJWT.sign(signer);

        // Parsing and serialising here allows us to cast like before.
        // The casting will be replaced in PYIC-5171 and so should this.
        return VerifiableCredential.fromValidJwt(
                userId, cri, SignedJWT.parse(signedJWT.serialize()));
    }

    private static VerifiableCredential signTestVcWithRSA(
            String userId, Cri cri, JWTClaimsSet claimsSet) throws Exception {
        var kf = KeyFactory.getInstance(KeyType.RSA.getValue());

        var privateKeySpec =
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(RSA_SIGNING_PRIVATE_KEY));
        var signer = new RSASSASigner(kf.generatePrivate(privateKeySpec));

        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet);

        signedJWT.sign(signer);

        return VerifiableCredential.fromValidJwt(
                userId, cri, SignedJWT.parse(signedJWT.serialize()));
    }

    public static IdentityCheckCredential vcClaimFailedWithCis(IdentityCheckSubject attributes) {
        return IdentityCheckCredential.builder()
                .withContext(List.of(W3_BASE_CONTEXT, DI_CONTEXT))
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(attributes)
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("DSJJSEE29392")
                                        .withVerificationScore(0)
                                        .withCi(List.of("A02", "A03"))
                                        .build()))
                .build();
    }
}
