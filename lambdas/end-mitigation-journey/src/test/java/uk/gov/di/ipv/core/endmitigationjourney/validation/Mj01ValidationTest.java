package uk.gov.di.ipv.core.endmitigationjourney.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1_PASSPORT_VC_MISSING_EVIDENCE;

@ExtendWith(MockitoExtension.class)
class Mj01ValidationTest {

    @Mock private ConfigService mockConfigService;

    @Test
    void shouldReturnListIfFraudVcFound() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().toEpochMilli(),
                                        Collections.emptyList())
                                .serialize());

        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        "test-user-id",
                        "test-sort-key",
                        "test-iss",
                        Instant.now().minusSeconds(100).toString(),
                        "TEST-01",
                        "1234",
                        "1234");

        Optional<List<String>> result =
                Mj01Validation.validateJourney(credentials, contraIndicatorItem, mockConfigService);

        assertTrue(result.isPresent());
        SignedJWT fraudJwt = SignedJWT.parse(result.get().get(0));
        JWTClaimsSet fraudClaimSet = fraudJwt.getJWTClaimsSet();
        assertEquals("test-fraud-iss", fraudClaimSet.getIssuer());
    }

    @Test
    void shouldReturnEmptyOptionalIfFraudVcMissing() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize());

        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        "test-user-id",
                        "test-sort-key",
                        "test-iss",
                        Instant.now().minusSeconds(100).toString(),
                        "TEST-01",
                        "1234",
                        "1234");

        Optional<List<String>> result =
                Mj01Validation.validateJourney(credentials, contraIndicatorItem, mockConfigService);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReturnOptionalEmptyIfFraudVcStillContainsCi() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize());

        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        "test-user-id",
                        "test-sort-key",
                        "test-iss",
                        Instant.now().minusSeconds(100).toString(),
                        "TEST-01",
                        "1234",
                        "1234");

        Optional<List<String>> result =
                Mj01Validation.validateJourney(credentials, contraIndicatorItem, mockConfigService);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReturnOptionalEmptyIfVcIsMissingEvidence() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials = List.of(M1_PASSPORT_VC_MISSING_EVIDENCE);

        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        "test-user-id",
                        "test-sort-key",
                        "test-iss",
                        Instant.now().minusSeconds(100).toString(),
                        "TEST-01",
                        "1234",
                        "1234");

        Optional<List<String>> result =
                Mj01Validation.validateJourney(credentials, contraIndicatorItem, mockConfigService);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReturnOptionalEmptyIfVcCannotBeParsed() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials = List.of("invalid-jwt");

        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        "test-user-id",
                        "test-sort-key",
                        "test-iss",
                        Instant.now().minusSeconds(100).toString(),
                        "TEST-01",
                        "1234",
                        "1234");

        Optional<List<String>> result =
                Mj01Validation.validateJourney(credentials, contraIndicatorItem, mockConfigService);

        assertTrue(result.isEmpty());
    }

    private CredentialIssuerConfig getTestFraudCriConfig() {
        return new CredentialIssuerConfig(
                "fraud",
                "fraud",
                true,
                URI.create("http://example.com/token"),
                URI.create("http://example.com/credential"),
                URI.create("http://example.com/authorize"),
                "ipv-core",
                "test-jwk",
                "test-jwk",
                "test-fraud-iss",
                URI.create("http://example.com/callback"),
                true,
                "main");
    }

    private SignedJWT generateTestVc(String iss, long nbf, List<String> cis)
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        JSONObject vcClaim = new JSONObject();
        List<CredentialEvidenceItem> credentialEvidenceList =
                List.of(
                        new CredentialEvidenceItem(
                                CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 2, cis));
        vcClaim.appendField("evidence", credentialEvidenceList);

        JWTClaimsSet jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .issuer(iss)
                        .notBeforeTime(new Date(nbf))
                        .claim("vc", vcClaim)
                        .build();
        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        jwtClaimsSet);
        signedJWT.sign(new ECDSASigner(getPrivateKey()));
        return signedJWT;
    }

    private static ECPrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
