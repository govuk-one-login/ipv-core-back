package uk.gov.di.ipv.core.library.vchelper;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;

import java.net.URI;
import java.net.URISyntaxException;

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
                            true,
                            new URI("https://example.com/token"),
                            new URI("https://example.com/credential"),
                            new URI("https://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "https://review-a.integration.account.gov.uk",
                            new URI("https://example.com/redirect"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @Test
    void shouldReturnTrueOnSuccessfulPassportVc() throws Exception {
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_PASSPORT_VC), addressConfig));
    }

    @Test
    void shouldReturnFalseOnFailedPassportVc() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_FAILED_PASSPORT_VC), addressConfig));
    }

    @Test
    void shouldReturnFalseOnPassportVcContainingCi() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI), addressConfig));
    }

    @Test
    void shouldReturnTrueOnSuccessfulAddressVc() throws Exception {
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_ADDRESS_VC), addressConfig));
    }

    @Test
    void shouldReturnTrueOnSuccessfulFraudVc() throws Exception {
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_FRAUD_VC), addressConfig));
    }

    @Test
    void shouldReturnFalseOnFailedFraudVc() throws Exception {
        assertFalse(VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_FAILED_FRAUD_VC), addressConfig));
    }

    @Test
    void shouldReturnFalseOnFraudVcContainingCi() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_FRAUD_VC_WITH_CI_D02), addressConfig));
    }

    @Test
    void shouldReturnTrueOnFraudVcContainingA01Ci() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_FRAUD_VC_WITH_CI_D02), addressConfig));
    }

    @Test
    void shouldReturnTrueOnSuccessfulKbvVc() throws Exception {
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_VERIFICATION_VC), addressConfig));
    }

    @Test
    void shouldReturnTrueOnSuccessfulDcmawVc() throws Exception {
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(M1B_DCMAW_VC), addressConfig));
    }

    @Test
    void shouldReturnFalseOnVcMissingEvidenceBlock() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1_PASSPORT_VC_MISSING_EVIDENCE), addressConfig));
    }

    @Test
    void shouldReturnTrueOnPassportVcContainingCiWhenIgnoringCi() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVcIgnoringCi(
                        SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI), addressConfig));
    }
}
