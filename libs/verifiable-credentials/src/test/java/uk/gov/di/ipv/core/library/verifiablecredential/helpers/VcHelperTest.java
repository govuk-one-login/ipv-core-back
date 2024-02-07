package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DRIVING_LICENCE_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_EXPERIAN_FAILED_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_F2F_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC_WITH_CI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1_PASSPORT_VC_MISSING_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_DRIVING_PERMIT_DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_EXPERIAN_FRAUD_SCORE_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_NINO_SUCCESSFUL;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_INVALID_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_MISSING_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL_WITH_ICAOCODE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_TICF;

@ExtendWith(MockitoExtension.class)
class VcHelperTest {
    @Mock private ConfigService configService;

    private static OauthCriConfig addressConfig = null;
    private static OauthCriConfig claimedIdentityConfig = null;

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
                Arguments.of("Fraud and activity VC", M1A_EXPERIAN_FRAUD_VC),
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

    @ParameterizedTest
    @MethodSource("UnsuccessfulTestCases")
    void shouldIdentifyUnsuccessfulVcs(String name, String vc) throws Exception {
        mockCredentialIssuerConfig();
        assertFalse(VcHelper.isSuccessfulVc(SignedJWT.parse(vc)), name);
    }

    @Test
    void shouldFilterVCsBasedOnProfileType_GPG45() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        TestFixtures.createVcStoreItem(
                                "userId", PASSPORT_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL),
                        TestFixtures.createVcStoreItem(
                                "userId", EXPERIAN_FRAUD_CRI, VC_EXPERIAN_FRAUD_SCORE_1),
                        TestFixtures.createVcStoreItem("userId", TICF_CRI, VC_TICF),
                        TestFixtures.createVcStoreItem(
                                "userId", HMRC_MIGRATION_CRI, VC_HMRC_MIGRATION));
        assertEquals(
                3, VcHelper.filterVCBasedOnProfileType(vcStoreItems, ProfileType.GPG45).size());
    }

    @Test
    void shouldFilterVCsBasedOnProfileType_operational() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        TestFixtures.createVcStoreItem(
                                "userId", PASSPORT_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL),
                        TestFixtures.createVcStoreItem(
                                "userId", EXPERIAN_FRAUD_CRI, VC_EXPERIAN_FRAUD_SCORE_1),
                        TestFixtures.createVcStoreItem("userId", TICF_CRI, VC_TICF),
                        TestFixtures.createVcStoreItem(
                                "userId", HMRC_MIGRATION_CRI, VC_HMRC_MIGRATION));
        assertEquals(
                2,
                VcHelper.filterVCBasedOnProfileType(vcStoreItems, ProfileType.OPERATIONAL_HMRC)
                        .size());
    }

    @Test
    void shouldExtractTxIdFromCredentials() throws ParseException {
        List<String> txns =
                VcHelper.extractTxnIdsFromCredentials(List.of(SignedJWT.parse(VC_NINO_SUCCESSFUL)));
        assertEquals(1, txns.size());
        assertEquals("e5b22348-c866-4b25-bb50-ca2106af7874", txns.get(0));
    }

    @Test
    void shouldExtractAgeFromCredential() throws ParseException {
        assertNotNull(
                VcHelper.extractAgeFromCredential(
                        SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL)));
    }

    @Test
    void shouldExtractAgeFromCredentialWithMissingBirthDate() throws ParseException {
        assertNull(
                VcHelper.extractAgeFromCredential(SignedJWT.parse(VC_PASSPORT_MISSING_BIRTH_DATE)));
    }

    @Test
    void shouldExtractAgeFromCredentialWithInvalidBirthDate() throws ParseException {
        assertNull(
                VcHelper.extractAgeFromCredential(SignedJWT.parse(VC_PASSPORT_INVALID_BIRTH_DATE)));
    }

    @Test
    void shouldChkIfDocUKIssuedForCredential() throws ParseException {
        assertTrue(
                VcHelper.checkIfDocUKIssuedForCredential(
                        SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL_WITH_ICAOCODE),
                        PASSPORT_CRI));
    }

    @Test
    void shouldChkIfDocUKIssuedForCredentialWithMissingICAOCode() throws ParseException {
        assertNull(
                VcHelper.checkIfDocUKIssuedForCredential(
                        SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL), PASSPORT_CRI));
    }

    @Test
    void shouldChkIfDocUKIssuedForCredentialForDL() throws ParseException {
        assertTrue(
                VcHelper.checkIfDocUKIssuedForCredential(
                        SignedJWT.parse(VC_DRIVING_PERMIT_DCMAW), DRIVING_LICENCE_CRI));
    }

    @Test
    void shouldChkIfDocUKIssuedForCredentialForDCMAW() throws ParseException {
        assertTrue(
                VcHelper.checkIfDocUKIssuedForCredential(
                        SignedJWT.parse(VC_DRIVING_PERMIT_DCMAW), DCMAW_CRI));
    }

    @Test
    void shouldCheckIsItOperationalVC() throws ParseException {
        assertTrue(VcHelper.isOperationalProfileVc(SignedJWT.parse(VC_HMRC_MIGRATION)));
        assertFalse(VcHelper.isOperationalProfileVc(SignedJWT.parse(M1A_PASSPORT_VC)));
    }

    private static Stream<Arguments> UnsuccessfulTestCases() {
        return Stream.of(
                Arguments.of("VC missing evidence", M1_PASSPORT_VC_MISSING_EVIDENCE),
                Arguments.of("Failed passport VC", M1A_FAILED_PASSPORT_VC),
                Arguments.of("Failed fraud check", M1A_EXPERIAN_FAILED_FRAUD_VC));
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
