package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScores;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC_WITH_CI_D02;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC_WITH_CI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1_PASSPORT_VC_MISSING_EVIDENCE;

class VcHelperTest {
    public static CredentialIssuerConfig addressConfig = null;

    static {
        try {
            addressConfig =
                    new CredentialIssuerConfig(
                            "address",
                            "address",
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "https://review-a.integration.account.gov.uk",
                            new URI("http://example.com/redirect"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @Test
    void shouldReturnTrueOnSuccessfulPassportVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_PASSPORT_VC),
                        addressConfig,
                        Collections.emptyMap(),
                        0));
    }

    @Test
    void shouldReturnFalseOnFailedPassportVc() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FAILED_PASSPORT_VC),
                        addressConfig,
                        Collections.emptyMap(),
                        0));
    }

    @Test
    void shouldReturnFalseOnPassportVcContainingCiExceedingThreshold() throws Exception {
        Map<String, ContraIndicatorScores> scoresMap = new HashMap<>();
        scoresMap.put("D02", new ContraIndicatorScores("D02", 45, 0, null));
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI), addressConfig, scoresMap, 40));
    }

    @Test
    void shouldReturnTrueOnSuccessfulAddressVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_ADDRESS_VC), addressConfig, Collections.emptyMap(), 0));
    }

    @Test
    void shouldReturnTrueOnSuccessfulFraudVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FRAUD_VC), addressConfig, Collections.emptyMap(), 0));
    }

    @Test
    void shouldReturnFalseOnFailedFraudVc() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FAILED_FRAUD_VC),
                        addressConfig,
                        Collections.emptyMap(),
                        0));
    }

    @Test
    void shouldReturnTrueOnFraudVcContainingCiWithinScoreThreshold() throws Exception {
        Map<String, ContraIndicatorScores> scoresMap = new HashMap<>();
        scoresMap.put("D02", new ContraIndicatorScores("D02", 99, 0, null));
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FRAUD_VC_WITH_CI_D02), addressConfig, scoresMap, 100));
    }

    @Test
    void shouldReturnFalseOnFraudVcContainingCiExceedingScoreThreshold() throws Exception {
        Map<String, ContraIndicatorScores> scoresMap = new HashMap<>();
        scoresMap.put("D02", new ContraIndicatorScores("D02", 101, 0, null));
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FRAUD_VC_WITH_CI_D02), addressConfig, scoresMap, 100));
    }

    @Test
    void shouldReturnTrueOnSuccessfulKbvVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_VERIFICATION_VC),
                        addressConfig,
                        Collections.emptyMap(),
                        0));
    }

    @Test
    void shouldReturnTrueOnSuccessfulDcmawVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1B_DCMAW_VC), addressConfig, Collections.emptyMap(), 0));
    }

    @Test
    void shouldReturnFalseOnVcMissingEvidenceBlock() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1_PASSPORT_VC_MISSING_EVIDENCE),
                        addressConfig,
                        Collections.emptyMap(),
                        0));
    }
}
