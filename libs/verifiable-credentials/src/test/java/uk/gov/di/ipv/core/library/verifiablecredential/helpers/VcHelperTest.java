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
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CHECK_EXPIRY_PERIOD_HOURS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_RESIDENCE_PERMIT_DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcFraudExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcFraudNotExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200NoEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250NoEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcInvalidVot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNullVot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportInvalidBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aMissingEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aWithCI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportMissingBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;

@ExtendWith(MockitoExtension.class)
class VcHelperTest {
    @Mock private ConfigService configService;

    private static Stream<Arguments> SuccessfulTestCases() throws Exception {
        return Stream.of(
                Arguments.of("Non-evidence VC", M1A_ADDRESS_VC),
                Arguments.of("Evidence VC", PASSPORT_NON_DCMAW_SUCCESSFUL_VC),
                Arguments.of("Evidence VC with CI", vcPassportM1aWithCI()),
                Arguments.of("Fraud and activity VC", M1A_EXPERIAN_FRAUD_VC),
                Arguments.of("Verification VC", vcVerificationM1a()),
                Arguments.of("Verification DCMAW VC", M1B_DCMAW_VC),
                Arguments.of("Verification F2F VC", vcF2fM1a()),
                Arguments.of("Verification Nino VC", vcNinoSuccessful()),
                Arguments.of("PCL250 no evidence VC", vcHmrcMigrationPCL250NoEvidence()),
                Arguments.of("PCL200 no evidence VC", vcHmrcMigrationPCL200NoEvidence()));
    }

    @ParameterizedTest
    @MethodSource("SuccessfulTestCases")
    void shouldIdentifySuccessfulVc(String name, VerifiableCredential vc) {
        assertTrue(VcHelper.isSuccessfulVc(vc), name);
    }

    @ParameterizedTest
    @MethodSource("UnsuccessfulTestCases")
    void shouldIdentifyUnsuccessfulVcs(String name, VerifiableCredential vc) {
        assertFalse(VcHelper.isSuccessfulVc(vc), name);
    }

    @Test
    void shouldFilterVCsBasedOnProfileType_GPG45() throws Exception {
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcTicf(),
                        vcHmrcMigrationPCL200());
        assertEquals(3, VcHelper.filterVCBasedOnProfileType(vcs, ProfileType.GPG45).size());
    }

    @Test
    void shouldFilterVCsBasedOnProfileType_operational() throws Exception {
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcHmrcMigrationPCL200());
        assertEquals(
                1, VcHelper.filterVCBasedOnProfileType(vcs, ProfileType.OPERATIONAL_HMRC).size());
    }

    @Test
    void shouldExtractTxIdFromIdentityCheckCredentials() {
        var txns = VcHelper.extractTxnIdsFromCredentials(List.of(vcNinoSuccessful()));

        assertEquals(1, txns.size());
        assertEquals("e5b22348-c866-4b25-bb50-ca2106af7874", txns.get(0));
    }

    @Test
    void shouldExtractTxIdDespiteNullEvidence() throws Exception {
        var txns =
                VcHelper.extractTxnIdsFromCredentials(
                        List.of(vcNinoSuccessful(), vcHmrcMigrationPCL200NoEvidence()));

        assertEquals(1, txns.size());
        assertEquals("e5b22348-c866-4b25-bb50-ca2106af7874", txns.get(0));
    }

    @Test
    void shouldExtractTxIdFromRiskAssessmentCredentials() {
        var txns = VcHelper.extractTxnIdsFromCredentials(List.of(vcTicf()));

        assertEquals(1, txns.size());
        assertEquals("963deeb5-a52c-4030-a69a-3184f77a4f18", txns.get(0));
    }

    @Test
    void shouldExtractEmptyTxIdFromAddressCredentials() {
        var txns = VcHelper.extractTxnIdsFromCredentials(List.of(vcAddressTwo()));

        assertEquals(0, txns.size());
    }

    @Test
    void shouldExtractAgeFromCredential() {
        assertNotNull(VcHelper.extractAgeFromCredential(PASSPORT_NON_DCMAW_SUCCESSFUL_VC));
    }

    @Test
    void shouldExtractAgeFromCredentialWithMissingBirthDate() {
        assertNull(VcHelper.extractAgeFromCredential(vcPassportMissingBirthDate()));
    }

    @Test
    void shouldExtractAgeFromCredentialWithInvalidBirthDate() {
        assertNull(VcHelper.extractAgeFromCredential(vcPassportInvalidBirthDate()));
    }

    @Test
    void shouldExtractAgeFromInvalidCredential() {
        assertNull(VcHelper.extractAgeFromCredential(vcAddressTwo()));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredential() {
        assertEquals(
                Boolean.TRUE,
                VcHelper.checkIfDocUKIssuedForCredential(PASSPORT_NON_DCMAW_SUCCESSFUL_VC));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredentialForDL() {
        assertEquals(Boolean.TRUE, VcHelper.checkIfDocUKIssuedForCredential(vcDrivingPermit()));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredentialForResidencePermit()
            throws ParseException, CredentialParseException {
        assertEquals(
                Boolean.TRUE,
                VcHelper.checkIfDocUKIssuedForCredential(
                        VerifiableCredential.fromValidJwt(
                                null, null, SignedJWT.parse(VC_RESIDENCE_PERMIT_DCMAW))));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredentialForDCMAW() {
        assertEquals(Boolean.TRUE, VcHelper.checkIfDocUKIssuedForCredential(vcDrivingPermit()));
    }

    @Test
    void shouldCheckIfDocUKIssuedForVcWithoutDocuments() {
        assertNull(VcHelper.checkIfDocUKIssuedForCredential(vcAddressTwo()));
    }

    @Test
    void shouldCheckIsItOperationalVC() throws Exception {
        assertTrue(VcHelper.isOperationalProfileVc(vcHmrcMigrationPCL200()));
        assertFalse(VcHelper.isOperationalProfileVc(PASSPORT_NON_DCMAW_SUCCESSFUL_VC));
    }

    @Test
    void shouldGetVcVot() throws Exception {
        assertEquals(Vot.PCL250, VcHelper.getVcVot(vcHmrcMigrationPCL250()));
    }

    @Test
    void shouldThrowUnrecognisedVotExceptionIfInvalidVcVot() {
        assertThrows(UnrecognisedVotException.class, () -> VcHelper.getVcVot(vcInvalidVot()));
    }

    @Test
    void shouldReturnNullIfVcVotIsNotPresent() throws Exception {
        assertNull(VcHelper.getVcVot(vcNullVot()));
    }

    @Test
    void shouldReturnTrueWhenVcIsExpired() {
        VcHelper.setConfigService(configService);
        // Arrange
        VerifiableCredential vc = vcFraudExpired();
        when(configService.getParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS)).thenReturn("1");

        // Act
        boolean result = VcHelper.isExpiredFraudVc(vc);

        // Assert
        assertTrue(result);
    }

    @Test
    void shouldReturnFalseWhenVcIsNotExpired() {
        VcHelper.setConfigService(configService);
        // Arrange
        VerifiableCredential vc = vcFraudNotExpired();
        when(configService.getParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS)).thenReturn("1");

        // Act
        boolean result = VcHelper.isExpiredFraudVc(vc);

        // Assert
        assertFalse(result);
    }

    private static Stream<Arguments> UnsuccessfulTestCases() {
        return Stream.of(
                Arguments.of("VC missing evidence", vcPassportM1aMissingEvidence()),
                Arguments.of("Failed passport VC", vcPassportM1aFailed()),
                Arguments.of("Failed fraud check", vcExperianFraudFailed()));
    }
}
