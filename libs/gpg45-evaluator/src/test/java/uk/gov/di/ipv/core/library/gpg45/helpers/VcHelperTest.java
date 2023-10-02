package uk.gov.di.ipv.core.library.gpg45.helpers;

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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC_WITH_CI;

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
    void shouldReturnTrueOnSuccessfulPassportVcForWithDefaultExcludedCredentialIssues()
            throws Exception {
        mockCredentialIssuerConfig();
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(M1A_PASSPORT_VC)));
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
