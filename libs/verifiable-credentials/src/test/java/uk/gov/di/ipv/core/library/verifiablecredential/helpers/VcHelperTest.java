package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.nimbusds.jwt.JWTClaimsSet;
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
import uk.gov.di.ipv.core.library.helpers.DateAndTimeHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_RESIDENCE_PERMIT_DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaExpiredSameDayAsNbf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitNullNbf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraud;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudApplicableAuthoritativeSourceFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudAvailableAuthoritativeSourceFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudEvidenceFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudMortalityFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudMortalityNonZeroScore;
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

    private static Stream<Arguments> UnsuccessfulTestCases() {
        return Stream.of(
                Arguments.of("VC missing evidence", vcWebPassportM1aMissingEvidence()),
                Arguments.of("Failed passport VC", vcWebPassportM1aFailed()),
                Arguments.of("Failed fraud check", vcExperianFraudEvidenceFailed()));
    }

    private final Clock fixedLondonClock =
            Clock.fixed(Instant.parse("2026-01-26T12:00:00Z"), DateAndTimeHelper.LONDON_TIMEZONE);

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
    void shouldReturnTrueWhenAllVcsAreExpired() {
        when(configService.getFraudCheckExpiryPeriodDays()).thenReturn(1);

        var vc = vcExperianFraudExpired();

        assertTrue(
                VcHelper.allFraudVcsAreExpiredOrFromUnavailableSource(
                        List.of(vc, vc), configService));
    }

    @Test
    void shouldReturnFalseWhenSomeVcsAreNotExpired() {
        when(configService.getFraudCheckExpiryPeriodDays()).thenReturn(1);

        var vcExpired = vcExperianFraudExpired();
        var vcNotExpired = vcExperianFraudNotExpired();

        assertFalse(
                VcHelper.allFraudVcsAreExpiredOrFromUnavailableSource(
                        List.of(vcExpired, vcNotExpired), configService));
    }

    @Test
    void shouldReturnTrueWhenAllVcsAreExpiredOrNotAvailable() {
        when(configService.getFraudCheckExpiryPeriodDays()).thenReturn(1);

        var vcExpired = vcExperianFraudExpired();
        var vcNotAvailable = vcExperianFraudAvailableAuthoritativeSourceFailed();

        assertTrue(
                VcHelper.allFraudVcsAreExpiredOrFromUnavailableSource(
                        List.of(vcExpired, vcNotAvailable), configService));
    }

    @Test
    void shouldReturnTrueWhenAllVcsAreExpiredUsingClock() {
        // Arrange
        when(configService.getFraudCheckExpiryPeriodDays()).thenReturn(1);

        var vc = vcExperianFraudExpired();

        // Act & Assert
        assertTrue(
                VcHelper.allFraudVcsAreExpiredOrFromUnavailableSource(
                        List.of(vc, vc), configService, fixedLondonClock));
    }

    @Test
    void shouldReturnFalseWhenSomeVcsAreNotExpiredUsingClock() {
        // Arrange
        when(configService.getFraudCheckExpiryPeriodDays()).thenReturn(1);

        var vcExpired = vcExperianFraudExpired();
        var vcNotExpired = vcExperianFraudNotExpired();

        // Act & Assert
        assertFalse(
                VcHelper.allFraudVcsAreExpiredOrFromUnavailableSource(
                        List.of(vcExpired, vcNotExpired), configService, fixedLondonClock));
    }

    @Test
    void shouldReturnTrueWhenAllVcsAreExpiredOrNotAvailableUsingClock() {
        // Arrange
        when(configService.getFraudCheckExpiryPeriodDays()).thenReturn(1);

        var vcExpired = vcExperianFraudExpired();
        var vcNotAvailable = vcExperianFraudAvailableAuthoritativeSourceFailed();

        // Act & Assert
        assertTrue(
                VcHelper.allFraudVcsAreExpiredOrFromUnavailableSource(
                        List.of(vcExpired, vcNotAvailable), configService, fixedLondonClock));
    }

    private static Stream<Arguments> FraudVcExpiryCases() {
        // In 2025 BST started at 01:00 on 30th March and ended at 01:00 26th October
        return Stream.of(
                Arguments.of(
                        "GMT -> GMT valid",
                        3,
                        "2025-01-29 10:30:00+0000",
                        "2025-01-31 23:59:59+0000",
                        false),
                Arguments.of(
                        "GMT -> GMT expired",
                        3,
                        "2025-01-29 10:30:00+0000",
                        "2025-02-01 00:00:00+0000",
                        true),
                Arguments.of(
                        "GMT -> BST valid",
                        3,
                        "2025-03-29 10:30:00+0000",
                        "2025-03-31 23:59:59+0100",
                        false),
                Arguments.of(
                        "GMT -> BST expired",
                        3,
                        "2025-03-29 10:30:00+0000",
                        "2025-04-01 00:00:00+0100",
                        true),
                Arguments.of(
                        "BST -> BST valid",
                        3,
                        "2025-07-29 10:30:00+0100",
                        "2025-07-31 23:59:59+0100",
                        false),
                Arguments.of(
                        "BST -> BST expired",
                        3,
                        "2025-07-29 10:30:00+0100",
                        "2025-08-01 00:00:00+0100",
                        true),
                Arguments.of(
                        "BST -> GMT valid",
                        3,
                        "2025-10-25 10:30:00+0100",
                        "2025-10-27 23:59:59+0000",
                        false),
                Arguments.of(
                        "BST -> GMT expired",
                        3,
                        "2025-10-25 10:30:00+0100",
                        "2025-10-28 00:00:00+0000",
                        true));
    }

    @ParameterizedTest
    @MethodSource("FraudVcExpiryCases")
    void shouldReturnTrueWhenVcHasExpiredCrossingFromGmtToBst(
            String description,
            int expiryPeriodInDays,
            String vcCreationDateTime,
            String timeOfExpiryTest,
            boolean expectedIsExpired) {
        when(configService.getFraudCheckExpiryPeriodDays()).thenReturn(expiryPeriodInDays);

        var vcCreationInstant =
                ZonedDateTime.parse(
                                vcCreationDateTime,
                                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ"))
                        .toInstant();

        Clock currentTime =
                Clock.fixed(
                        ZonedDateTime.parse(
                                        timeOfExpiryTest,
                                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ"))
                                .toInstant(),
                        ZoneOffset.UTC);

        var fraudVc = vcExperianFraud(vcCreationInstant);

        assertEquals(
                expectedIsExpired,
                VcHelper.isExpiredFraudVc(fraudVc, configService, currentTime),
                description);
    }

    @Test
    void
            hasNonFatalFraudCheckFailureShouldReturnTrueForApplicableAuthoritativeSourceFailedFraudCheck() {

        // Arrange
        var vc = vcExperianFraudApplicableAuthoritativeSourceFailed();

        // Act
        var result = VcHelper.hasNonFatalFraudCheckFailure(vc);

        // Assert
        assertTrue(result);
    }

    @Test
    void
            hasNonFatalFraudCheckFailureShouldReturnTrueForAuthoritativeAvailableSourceFailedFraudCheck() {

        // Arrange
        var vc = vcExperianFraudAvailableAuthoritativeSourceFailed();

        // Act
        var result = VcHelper.hasNonFatalFraudCheckFailure(vc);

        // Assert
        assertTrue(result);
    }

    @Test
    void hasNonFatalFraudCheckFailureShouldReturnTrueForMortalityFailedFraudCheck() {

        // Arrange
        var vc = vcExperianFraudMortalityFailed();

        // Act
        var result = VcHelper.hasNonFatalFraudCheckFailure(vc);

        // Assert
        assertTrue(result);
    }

    @Test
    void
            isFraudScoreOptionalForGpg45EvaluationShouldReturnTrueForApplicableAuthoritativeSourceFailedFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudApplicableAuthoritativeSourceFailed(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.isFraudScoreOptionalForGpg45Evaluation(vcs);

        // Assert
        assertTrue(result);
    }

    @Test
    void
            isFraudScoreOptionalForGpg45EvaluationShouldReturnTrueForAuthoritativeAvailableSourceFailedFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudAvailableAuthoritativeSourceFailed(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.isFraudScoreOptionalForGpg45Evaluation(vcs);

        // Assert
        assertTrue(result);
    }

    @Test
    void isFraudScoreOptionalForGpg45EvaluationShouldReturnTrueForFailedMortalityCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudMortalityFailed(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.isFraudScoreOptionalForGpg45Evaluation(vcs);

        // Assert
        assertTrue(result);
    }

    @Test
    void isFraudScoreOptionalForGpg45EvaluationShouldReturnFalseForOtherFailedFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudEvidenceFailed(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.isFraudScoreOptionalForGpg45Evaluation(vcs);

        // Assert
        assertFalse(result);
    }

    @Test
    void
            isFraudScoreOptionalForGpg45EvaluationShouldReturnFalseForailedMortalityCheckWithNonZeroFraudScore() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudMortalityNonZeroScore(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.isFraudScoreOptionalForGpg45Evaluation(vcs);

        // Assert
        assertFalse(result);
    }

    @Test
    void isFraudScoreOptionalForGpg45EvaluationShouldReturnFalseForSuccessfulFraudCheck() {

        // Arrange
        var vcs =
                List.of(
                        vcDcmawPassport(),
                        vcAddressM1a(),
                        vcExperianFraudScoreOne(),
                        vcExperianKbvM1a());

        // Act
        var result = VcHelper.isFraudScoreOptionalForGpg45Evaluation(vcs);

        // Assert
        assertFalse(result);
    }

    @Test
    void isFraudScoreOptionalForGpg45EvaluationShouldReturnFalseForMissingFraudCheck() {

        // Arrange
        var vcs = List.of(vcDcmawPassport(), vcAddressM1a(), vcExperianKbvM1a());

        // Act
        var result = VcHelper.isFraudScoreOptionalForGpg45Evaluation(vcs);

        // Assert
        assertFalse(result);
    }

    @Test
    void hasUnavailableFraudCheckShouldReturnTrueForUnavailableFraudCheck() {

        // Arrange
        var vc = vcExperianFraudAvailableAuthoritativeSourceFailed();

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

    private static Stream<Arguments> provideTestArgumentsForIsExpiredDrivingPermitVc() {
        return Stream.of(
                Arguments.of(
                        "expired DL and past validity period, GMT current time",
                        vcDcmawDrivingPermitDvaExpired(), // expiry: "2020-10-01", nbf:
                        // 2024-01-23T05:08:41
                        5,
                        "2024-02-01 00:00:00+0000",
                        true),
                Arguments.of(
                        "expired DL but within validity period, GMT current time",
                        vcDcmawDrivingPermitDvaExpired(), // expiry: "2020-10-01", nbf:
                        // 2024-01-23T05:08:41
                        10,
                        "2024-01-25 00:00:00+0000",
                        false),
                Arguments.of(
                        "DL expires same day as NBF, GMT current time",
                        vcDcmawDrivingPermitDvaExpiredSameDayAsNbf(), // expiry: 2020-10-01, nbf:
                        // 2020-10-01T13:30:00
                        180,
                        "2020-10-02 00:00:00+0000",
                        false),
                Arguments.of(
                        "expired DL but within validity period, BST current time",
                        vcDcmawDrivingPermitDvaExpired(), // expiry: "2020-10-01", nbf:
                        // 2024-01-23T05:08:41
                        1,
                        "2024-01-24 00:10:00+0100",
                        false),
                Arguments.of(
                        "expired DL and past validity period, BST current time",
                        vcDcmawDrivingPermitDvaExpired(), // expiry: "2020-10-01", nbf:
                        // 2024-01-23T05:08:41
                        1,
                        "2024-01-24 01:00:00+0100",
                        true));
    }

    @ParameterizedTest
    @MethodSource("provideTestArgumentsForIsExpiredDrivingPermitVc")
    void isExpiredDrivingPermitVcShouldReturnCorrectValueForAGivenDrivingPermitVc(
            String description,
            VerifiableCredential dcmawVc,
            int validityDurationDays,
            String currentDateTime,
            boolean expectedHasExpired) {
        // Arrange
        when(configService.getDcmawExpiredDlValidityPeriodDays()).thenReturn(validityDurationDays);

        Clock currentTime =
                Clock.fixed(
                        ZonedDateTime.parse(
                                        currentDateTime,
                                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ"))
                                .toInstant(),
                        ZoneOffset.UTC);

        // Act
        var result = VcHelper.isExpiredDrivingPermitVc(dcmawVc, configService, currentTime);

        // Assert
        assertEquals(expectedHasExpired, result, description);
    }

    @Test
    void isExpiredDrivingPermitVcShouldReturnFalseWhenMissingValidityPeriodDays() {
        // Arrange
        when(configService.getDcmawExpiredDlValidityPeriodDays()).thenReturn(null);

        Clock currentTime =
                Clock.fixed(
                        ZonedDateTime.parse(
                                        "2024-01-24 01:00:00+0100",
                                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ"))
                                .toInstant(),
                        ZoneOffset.UTC);

        // Act
        // The below DCMAW VC has expiry: "2020-10-01", nbf: 2024-01-23T05:08:41
        var result =
                VcHelper.isExpiredDrivingPermitVc(
                        vcDcmawDrivingPermitDvaExpired(), configService, currentTime);

        // Assert
        assertFalse(result);
    }

    @Test
    void isExpiredDrivingPermitVcShouldReturnFalseWhenVcIsMissingNbf() {
        // Arrange
        when(configService.getDcmawExpiredDlValidityPeriodDays()).thenReturn(180);

        Clock currentTime =
                Clock.fixed(
                        ZonedDateTime.parse(
                                        "2024-01-24 01:00:00+0100",
                                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssZ"))
                                .toInstant(),
                        ZoneOffset.UTC);
        // Act
        // The below DCMAW VC has expiry: "2020-10-01", nbf: null
        var result =
                VcHelper.isExpiredDrivingPermitVc(
                        vcDrivingPermitNullNbf(), configService, currentTime);

        // Assert
        assertFalse(result);
    }

    @Test
    void extractNbfShouldReturnEmptyWhenVcIsNull() {
        // Arrange & Act
        var result = VcHelper.extractNbf(null);

        // Assert
        assertTrue(result.isEmpty());
    }

    @Test
    void extractNbfShouldReturnEmptyWhenClaimsSetIsNull() {
        // Arrange
        var vc = mock(VerifiableCredential.class);
        when(vc.getClaimsSet()).thenReturn(null);

        // Act
        var result = VcHelper.extractNbf(vc);

        // Assert
        assertTrue(result.isEmpty());
    }

    @Test
    void extractNbfShouldReturnEmptyWhenNotBeforeTimeIsNull() {
        // Arrange
        var claimsSet = mock(JWTClaimsSet.class);
        when(claimsSet.getNotBeforeTime()).thenReturn(null);

        var vc = mock(VerifiableCredential.class);
        when(vc.getClaimsSet()).thenReturn(claimsSet);

        // Act
        var result = VcHelper.extractNbf(vc);

        // Assert
        assertTrue(result.isEmpty());
    }

    @Test
    void extractNbfShouldReturnInstantWhenNotBeforeTimeIsPresent() {
        // Arrange
        var nbfDate = new Date();
        var claimsSet = mock(JWTClaimsSet.class);
        when(claimsSet.getNotBeforeTime()).thenReturn(nbfDate);

        var vc = mock(VerifiableCredential.class);
        when(vc.getClaimsSet()).thenReturn(claimsSet);

        // Act
        var result = VcHelper.extractNbf(vc);

        // Assert
        assertTrue(result.isPresent());
        assertEquals(nbfDate.toInstant(), result.get());
    }
}
