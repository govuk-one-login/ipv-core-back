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
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcInvalidVot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNullVot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportInvalidBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aMissingEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aWithCI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportMissingBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportNonDcmawSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;

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

    private static Stream<Arguments> SuccessfulTestCases() throws Exception {
        return Stream.of(
                Arguments.of("Non-evidence VC", M1A_ADDRESS_VC),
                Arguments.of("Evidence VC", vcPassportNonDcmawSuccessful()),
                Arguments.of("Evidence VC with CI", vcPassportM1aWithCI()),
                Arguments.of("Fraud and activity VC", M1A_EXPERIAN_FRAUD_VC),
                Arguments.of("Verification VC", vcVerificationM1a()),
                Arguments.of("Verification DCMAW VC", M1B_DCMAW_VC),
                Arguments.of("Verification F2F VC", vcF2fM1a()),
                Arguments.of("Verification Nino VC", vcNinoSuccessful()),
                Arguments.of("Verification TICF VC", vcTicf()));
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
    void shouldFilterVCsBasedOnProfileType_GPG45() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        TestFixtures.createVcStoreItem(
                                "userId", PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                        TestFixtures.createVcStoreItem(
                                "userId", EXPERIAN_FRAUD_CRI, vcExperianFraudScoreOne()),
                        TestFixtures.createVcStoreItem("userId", TICF_CRI, vcTicf()),
                        TestFixtures.createVcStoreItem(
                                "userId", HMRC_MIGRATION_CRI, vcHmrcMigration()));
        assertEquals(
                3, VcHelper.filterVCBasedOnProfileType(vcStoreItems, ProfileType.GPG45).size());
    }

    @Test
    void shouldFilterVCsBasedOnProfileType_operational() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        TestFixtures.createVcStoreItem(
                                "userId", PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                        TestFixtures.createVcStoreItem(
                                "userId", EXPERIAN_FRAUD_CRI, vcExperianFraudScoreOne()),
                        TestFixtures.createVcStoreItem("userId", TICF_CRI, vcTicf()),
                        TestFixtures.createVcStoreItem(
                                "userId", HMRC_MIGRATION_CRI, vcHmrcMigration()));
        assertEquals(
                2,
                VcHelper.filterVCBasedOnProfileType(vcStoreItems, ProfileType.OPERATIONAL_HMRC)
                        .size());
    }

    @Test
    void shouldExtractTxIdFromCredentials() throws Exception {
        List<String> txns =
                VcHelper.extractTxnIdsFromCredentials(List.of(SignedJWT.parse(vcNinoSuccessful())));
        assertEquals(1, txns.size());
        assertEquals("e5b22348-c866-4b25-bb50-ca2106af7874", txns.get(0));
    }

    @Test
    void shouldExtractAgeFromCredential() throws Exception {
        assertNotNull(
                VcHelper.extractAgeFromCredential(SignedJWT.parse(vcPassportNonDcmawSuccessful())));
    }

    @Test
    void shouldExtractAgeFromCredentialWithMissingBirthDate() throws Exception {
        assertNull(
                VcHelper.extractAgeFromCredential(SignedJWT.parse(vcPassportMissingBirthDate())));
    }

    @Test
    void shouldExtractAgeFromCredentialWithInvalidBirthDate() throws Exception {
        assertNull(
                VcHelper.extractAgeFromCredential(SignedJWT.parse(vcPassportInvalidBirthDate())));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredential() throws Exception {
        assertEquals(
                Boolean.TRUE,
                VcHelper.checkIfDocUKIssuedForCredential(
                        SignedJWT.parse(vcPassportNonDcmawSuccessful())));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredentialForDL() throws Exception {
        assertEquals(
                Boolean.TRUE,
                VcHelper.checkIfDocUKIssuedForCredential(SignedJWT.parse(vcDrivingPermit())));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredentialForDCMAW() throws Exception {
        assertEquals(
                Boolean.TRUE,
                VcHelper.checkIfDocUKIssuedForCredential(SignedJWT.parse(vcDrivingPermit())));
    }

    @Test
    void shouldCheckIsItOperationalVC() throws Exception {
        assertTrue(VcHelper.isOperationalProfileVc(SignedJWT.parse(vcHmrcMigration())));
        assertFalse(
                VcHelper.isOperationalProfileVc(SignedJWT.parse(vcPassportNonDcmawSuccessful())));
    }

    @Test
    void shouldGetVcVot() throws Exception {
        assertEquals(Vot.PCL250, VcHelper.getVcVot(SignedJWT.parse(vcHmrcMigration())));
    }

    @Test
    void shouldThrowUnrecognisedVotExceptionIfInvalidVcVot() {
        assertThrows(
                UnrecognisedVotException.class,
                () -> VcHelper.getVcVot(SignedJWT.parse(vcInvalidVot())));
    }

    @Test
    void shouldReturnNullIfVcVotIsNotPresent() throws Exception {
        assertNull(VcHelper.getVcVot(SignedJWT.parse(vcNullVot())));
    }

    private static Stream<Arguments> UnsuccessfulTestCases() {
        return Stream.of(
                Arguments.of("VC missing evidence", vcPassportM1aMissingEvidence()),
                Arguments.of("Failed passport VC", vcPassportM1aFailed()),
                Arguments.of("Failed fraud check", vcExperianFraudFailed()));
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
