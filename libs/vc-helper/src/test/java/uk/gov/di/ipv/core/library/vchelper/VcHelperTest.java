package uk.gov.di.ipv.core.library.vchelper;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.Set;

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
    public static Set<String> EXCLUDED_CREDENTIAL_ISSUERS =
            Set.of("https://review-a.integration.account.gov.uk");

    @Test
    void shouldReturnTrueOnSuccessfulPassportVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_PASSPORT_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnFalseOnFailedPassportVc() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FAILED_PASSPORT_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnFalseOnPassportVcContainingCi() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnTrueOnSuccessfulAddressVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_ADDRESS_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnTrueOnSuccessfulFraudVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FRAUD_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnFalseOnFailedFraudVc() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FAILED_FRAUD_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnFalseOnFraudVcContainingCi() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FRAUD_VC_WITH_CI_D02), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnTrueOnFraudVcContainingA01Ci() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_FRAUD_VC_WITH_CI_D02), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnTrueOnSuccessfulKbvVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_VERIFICATION_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnTrueOnSuccessfulDcmawVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1B_DCMAW_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnFalseOnVcMissingEvidenceBlock() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1_PASSPORT_VC_MISSING_EVIDENCE),
                        EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnTrueOnPassportVcContainingCiWhenIgnoringCi() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVcIgnoringCi(
                        SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI), EXCLUDED_CREDENTIAL_ISSUERS));
    }
}
