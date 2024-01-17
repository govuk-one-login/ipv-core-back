package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_F2F_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC_WITH_CI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1_PASSPORT_VC_MISSING_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_NINO_SUCCESSFUL;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_TICF;

@ExtendWith(MockitoExtension.class)
class VcHelperTest {
    @Mock private ConfigService configService;

    public static Set<String> EXCLUDED_CREDENTIAL_ISSUERS =
            Set.of("https://review-a.integration.account.gov.uk");

    public static OauthCriConfig addressConfig = null;
    public static OauthCriConfig claimedIdentityConfig = null;

    static {
        try {
            addressConfig = createOauthCriConfig("https://review-a.integration.account.gov.uk");
            claimedIdentityConfig =
                    createOauthCriConfig("https://review-c.integration.account.gov.uk");
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
                Arguments.of("Verification VC", M1A_VERIFICATION_VC),
                Arguments.of("Verification DCMAW VC", M1B_DCMAW_VC),
                Arguments.of("Verification F2F VC", M1A_F2F_VC),
                Arguments.of("Verification Nino VC", VC_NINO_SUCCESSFUL),
                Arguments.of("Verification TICF VC", VC_TICF));
    }

    @ParameterizedTest
    @MethodSource("SuccessfulTestCases")
    void shouldIdentifySuccessfulVc(String name, String vc) throws Exception {
        mockCredentialIssuerConfig();
        assertTrue(VcHelper.isSuccessfulVc(SignedJWT.parse(vc)), name);
    }

    @ParameterizedTest
    @MethodSource("SuccessfulTestCases")
    void shouldIdentifySuccessfulVcs(String name, String vc) throws Exception {
        mockCredentialIssuerConfig();
        assertTrue(VcHelper.isSuccessfulVcs(List.of(SignedJWT.parse(vc))), name);
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

    private static OauthCriConfig createOauthCriConfig(String componentId)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://example.com/token"))
                .credentialUrl(new URI("http://example.com/credential"))
                .authorizeUrl(new URI("http://example.com/authorize"))
                .clientId("ipv-core")
                .signingKey("test-jwk")
                .encryptionKey("test-encryption-jwk")
                .componentId(componentId)
                .clientCallbackUrl(new URI("http://example.com/redirect"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
