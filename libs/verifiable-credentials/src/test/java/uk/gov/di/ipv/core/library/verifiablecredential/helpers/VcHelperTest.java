package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC_WITH_CI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
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

    private static Stream<Arguments> SuccessfulTestCases() {
        return Stream.of(
                Arguments.of("Non-evidence VC", M1A_ADDRESS_VC),
                Arguments.of("Evidence VC", M1A_PASSPORT_VC),
                Arguments.of("Evidence VC with CI", M1A_PASSPORT_VC_WITH_CI),
                Arguments.of("Fraud and activity VC", M1A_FRAUD_VC),
                Arguments.of("Verification VC", M1A_VERIFICATION_VC));
    }

    @ParameterizedTest
    @MethodSource("SuccessfulTestCases")
    void shouldIdentifySuccessfulVcs(String name, String vc) throws Exception {
        mockCredentialIssuerConfig();
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(vc)), name);
    }

    private static Stream<Arguments> UnsuccessfulTestCases() {
        return Stream.of(
                Arguments.of("VC missing evidence", M1_PASSPORT_VC_MISSING_EVIDENCE),
                Arguments.of("Failed passport VC", M1A_FAILED_PASSPORT_VC),
                Arguments.of("Failed fraud check", M1A_FAILED_FRAUD_VC));
    }

    @ParameterizedTest
    @MethodSource("UnsuccessfulTestCases")
    void shouldIdentifyUnsuccessfulVcs(String name, String vc) throws Exception {
        mockCredentialIssuerConfig();
        assertFalse(VcHelper.isSuccessfulVc(SignedJWT.parse(vc)), name);
    }

    private void mockCredentialIssuerConfig() {
        VcHelper.setConfigService(configService);
        when(configService.getComponentId(ADDRESS_CRI)).thenReturn(addressConfig.getComponentId());
        when(configService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig.getComponentId());
    }
}
