package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_RESIDENCE_PERMIT_DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudApplicableAuthoritativeSourceFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudAvailableAuthoritativeFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudEvidenceFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudNotExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianKbvM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcInvalidVot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoIdentityCheckSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNullVot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcP2Vot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportInvalidBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportM1aFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportM1aMissingEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportM1aWithCiButValidity2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportMissingBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;

@ExtendWith(MockitoExtension.class)
class VcHelperTest {
    @Mock private ConfigService configService;

    private static Stream<Arguments> SuccessfulTestCases() {
        return Stream.of(
                Arguments.of("Non-evidence VC", vcAddressM1a()),
                Arguments.of("Evidence VC", vcWebPassportSuccessful()),
                Arguments.of("Evidence VC with CI", vcWebPassportM1aWithCiButValidity2()),
                Arguments.of("Fraud and activity VC", vcExperianFraudM1a()),
                Arguments.of("Verification VC", vcExperianKbvM1a()),
                Arguments.of("Verification DCMAW VC", vcDcmawDrivingPermitDvaM1b()),
                Arguments.of("Verification F2F VC", vcF2fPassportPhotoM1a()),
                Arguments.of("Verification Nino VC", vcNinoIdentityCheckSuccessful()));
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
    void shouldExtractTxnIdDespiteNullEvidence() {
        var txns = VcHelper.extractTxnIdsFromCredentials(List.of(vcNinoIdentityCheckSuccessful()));

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
        assertNotNull(VcHelper.extractAgeFromCredential(vcWebPassportSuccessful()));
    }

    @Test
    void shouldExtractAgeFromCredentialWithMissingBirthDate() {
        assertNull(VcHelper.extractAgeFromCredential(vcWebPassportMissingBirthDate()));
    }

    @Test
    void shouldExtractAgeFromCredentialWithInvalidBirthDate() {
        assertNull(VcHelper.extractAgeFromCredential(vcWebPassportInvalidBirthDate()));
    }

    @Test
    void shouldExtractAgeFromInvalidCredential() {
        assertNull(VcHelper.extractAgeFromCredential(vcAddressTwo()));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredential() {
        assertEquals(
                Boolean.TRUE, VcHelper.checkIfDocUKIssuedForCredential(vcWebPassportSuccessful()));
    }

    @Test
    void shouldCheckIfDocUKIssuedForCredentialForDL() {
        assertEquals(
                Boolean.TRUE,
                VcHelper.checkIfDocUKIssuedForCredential(vcWebDrivingPermitDvaValid()));
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
        assertEquals(
                Boolean.TRUE,
                VcHelper.checkIfDocUKIssuedForCredential(vcWebDrivingPermitDvaValid()));
    }

    @Test
    void shouldCheckIfDocUKIssuedForVcWithoutDocuments() {
        assertNull(VcHelper.checkIfDocUKIssuedForCredential(vcAddressTwo()));
    }

    @Test
    void shouldGetVcVot() throws Exception {
        assertEquals(Vot.P2, VcHelper.getVcVot(vcP2Vot()));
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
        when(configService.getFraudCheckExpiryPeriodHours()).thenReturn(1);

        var vc = vcExperianFraudExpired();

        assertTrue(VcHelper.isExpiredFraudVc(vc, configService));
    }

    @Test
    void shouldReturnFalseWhenVcIsNotExpired() {
        when(configService.getFraudCheckExpiryPeriodHours()).thenReturn(1);

        var vc = vcExperianFraudNotExpired();

        assertFalse(VcHelper.isExpiredFraudVc(vc, configService));
    }

    private static Stream<Arguments> UnsuccessfulTestCases() {
        return Stream.of(
                Arguments.of("VC missing evidence", vcWebPassportM1aMissingEvidence()),
                Arguments.of("Failed passport VC", vcWebPassportM1aFailed()),
                Arguments.of("Failed fraud check", vcExperianFraudEvidenceFailed()));
    }

    @Test
    void
            hasUnavailableOrNotApplicableFraudCheckShouldReturnTrueForApplicableAuthoritativeSourceFailedFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudApplicableAuthoritativeSourceFailed(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.hasUnavailableOrNotApplicableFraudCheck(vcs);

        // Assert
        assertTrue(result);
    }

    @Test
    void
            hasUnavailableOrNotApplicableFraudCheckShouldReturnTrueForAuthoritativeAvailableSourceFailedFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudAvailableAuthoritativeFailed(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.hasUnavailableOrNotApplicableFraudCheck(vcs);

        // Assert
        assertTrue(result);
    }

    @Test
    void hasUnavailableOrNotApplicableFraudCheckShouldReturnFalseForOtherFailedFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudEvidenceFailed(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.hasUnavailableOrNotApplicableFraudCheck(vcs);

        // Assert
        assertFalse(result);
    }

    @Test
    void hasUnavailableOrNotApplicableFraudCheckShouldReturnFalseForSuccessfulFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudScoreOne(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.hasUnavailableOrNotApplicableFraudCheck(vcs);

        // Assert
        assertFalse(result);
    }

    @Test
    void hasUnavailableOrNotApplicableFraudCheckShouldReturnFalseForMissingFraudCheck() {

        // Arrange
        var vcs = List.of(vcDcmawPassport(), vcAddressM1a(), vcExperianKbvM1a());

        // Act
        var result = VcHelper.hasUnavailableOrNotApplicableFraudCheck(vcs);

        // Assert
        assertFalse(result);
    }

    @Test
    void hasUnavailableFraudCheckShouldReturnTrueForUnavailableFraudCheck() {

        // Arrange
        var vc = vcExperianFraudAvailableAuthoritativeFailed();

        // Act
        var result = VcHelper.hasUnavailableFraudCheck(vc);

        // Assert
        assertTrue(result);
    }

    @Test
    void hasUnavailableFraudCheckShouldReturnFalseForSuccessfulFraudCheck() {

        // Act
        var result = VcHelper.hasUnavailableFraudCheck(vcExperianFraudScoreOne());

        // Assert
        assertFalse(result);
    }

    @Test
    void hasUnavailableFraudCheckShouldReturnFalseForMissingFraudCheck() {

        // Act
        var result = VcHelper.hasUnavailableFraudCheck(vcDcmawPassport());

        // Assert
        assertFalse(result);
    }
}
