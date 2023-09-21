package uk.gov.di.ipv.core.library.vchelper;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_EVIDENCE_ACTIVITY_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_EVIDENCE_NA_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_F2F_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC_WITH_CI_D02;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC_WITH_CI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1_PASSPORT_VC_MISSING_EVIDENCE;

@ExtendWith(MockitoExtension.class)
class VcHelperTest {
    @Mock private ConfigService configService;

    public static Set<String> EXCLUDED_CREDENTIAL_ISSUERS =
            Set.of("https://review-a.integration.account.gov.uk");

    public static CredentialIssuerConfig addressConfig = null;
    public static CredentialIssuerConfig claimedIdentityConfig = null;

    static {
        try {
            addressConfig =
                    new CredentialIssuerConfig(
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "https://review-a.integration.account.gov.uk",
                            new URI("http://example.com/redirect"),
                            true);
            claimedIdentityConfig =
                    new CredentialIssuerConfig(
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "https://review-c.integration.account.gov.uk",
                            new URI("http://example.com/redirect"),
                            true);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @Test
    void shouldReturnTrueOnSuccessfulPassportVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_PASSPORT_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnTrueOnSuccessfulPassportVcForWithDefaultExcludedCredentialIssues()
            throws Exception {
        mockCredentialIssuerConfig();
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_PASSPORT_VC)));
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
    void shouldReturnTrueOnSuccessfulF2FVc() throws Exception {
        assertTrue(
                VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_F2F_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnFalseOnSuccessfulForEvidenceTypeUnknown() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_EVIDENCE_NA_VC), EXCLUDED_CREDENTIAL_ISSUERS));
    }

    @Test
    void shouldReturnFalseOnSuccessfulForEvidenceTypeActivity() throws Exception {
        assertFalse(
                VcHelper.isSuccessfulVc(
                        SignedJWT.parse(M1A_EVIDENCE_ACTIVITY_VC), EXCLUDED_CREDENTIAL_ISSUERS));
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

    @Test
    void shouldReturnTrueOnPassportVcContainingCiWhenIgnoringCiAndWithoutExcludedCredetialIssuers()
            throws Exception {
        mockCredentialIssuerConfig();
        assertTrue(VcHelper.isSuccessfulVcIgnoringCi(SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI)));
    }

    private void mockCredentialIssuerConfig() {
        VcHelper.setConfigService(configService);
        when(configService.getComponentId(ADDRESS_CRI)).thenReturn(addressConfig.getComponentId());
        when(configService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig.getComponentId());
    }
}
