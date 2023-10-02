package uk.gov.di.ipv.core.library.gpg45.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.exceptions.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem.EvidenceType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialEvidenceItemTest {
    @Test
    void shouldConstructorWithEvidenceTypeAndScore() {
        CredentialEvidenceItem credentialEvidenceItem1 =
                new CredentialEvidenceItem(EvidenceType.ACTIVITY, 10, Collections.emptyList());
        assertEquals(10, credentialEvidenceItem1.getActivityHistoryScore());
        assertNull(credentialEvidenceItem1.getIdentityFraudScore());
        assertNull(credentialEvidenceItem1.getVerificationScore());

        CredentialEvidenceItem credentialEvidenceItem2 =
                new CredentialEvidenceItem(
                        EvidenceType.IDENTITY_FRAUD, 20, Collections.emptyList());
        assertNull(credentialEvidenceItem2.getActivityHistoryScore());
        assertEquals(20, credentialEvidenceItem2.getIdentityFraudScore());
        assertNull(credentialEvidenceItem2.getVerificationScore());

        CredentialEvidenceItem credentialEvidenceItem3 =
                new CredentialEvidenceItem(EvidenceType.VERIFICATION, 30, Collections.emptyList());
        assertNull(credentialEvidenceItem3.getActivityHistoryScore());
        assertNull(credentialEvidenceItem3.getIdentityFraudScore());
        assertEquals(30, credentialEvidenceItem3.getVerificationScore());
    }

    @Test
    void shouldConstructorWithStrengthValidityCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(15, 25, Collections.emptyList());
        assertEquals(15, credentialEvidenceItem.getStrengthScore());
        assertEquals(25, credentialEvidenceItem.getValidityScore());
    }

    @Test
    void shouldFullArgConstructor() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        10,
                        20,
                        30,
                        40,
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList());
        assertEquals(10, credentialEvidenceItem.getStrengthScore());
        assertEquals(20, credentialEvidenceItem.getValidityScore());
        assertEquals(30, credentialEvidenceItem.getActivityHistoryScore());
        assertEquals(40, credentialEvidenceItem.getVerificationScore());
    }

    @Test
    void shouldGetTypeActivity() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(EvidenceType.ACTIVITY, 30, Collections.emptyList());
        assertEquals(EvidenceType.ACTIVITY, credentialEvidenceItem.getType());
        assertEquals(30, credentialEvidenceItem.getActivityHistoryScore());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotActivity")
    void shouldNotGetTypeActivity(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.ACTIVITY, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotActivity() {
        return Stream.of(
                CredentialEvidenceItem.builder().build(),
                CredentialEvidenceItem.builder()
                        .activityHistoryScore(10)
                        .identityFraudScore(10)
                        .build(),
                CredentialEvidenceItem.builder().activityHistoryScore(10).strengthScore(10).build(),
                CredentialEvidenceItem.builder().activityHistoryScore(10).validityScore(10).build(),
                CredentialEvidenceItem.builder()
                        .activityHistoryScore(10)
                        .verificationScore(10)
                        .build());
    }

    @Test
    void shouldGetTypeIdentityFraud() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        EvidenceType.IDENTITY_FRAUD, 30, Collections.emptyList());
        assertEquals(EvidenceType.IDENTITY_FRAUD, credentialEvidenceItem.getType());
        assertEquals(30, credentialEvidenceItem.getIdentityFraudScore());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotIdentityFraud")
    void shouldNotGetTypeIdentityFraud(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.IDENTITY_FRAUD, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotIdentityFraud() {
        return Stream.of(
                CredentialEvidenceItem.builder().build(),
                CredentialEvidenceItem.builder()
                        .identityFraudScore(10)
                        .activityHistoryScore(10)
                        .build(),
                CredentialEvidenceItem.builder().identityFraudScore(10).strengthScore(10).build(),
                CredentialEvidenceItem.builder().identityFraudScore(10).validityScore(10).build(),
                CredentialEvidenceItem.builder()
                        .identityFraudScore(10)
                        .verificationScore(10)
                        .build());
    }

    @Test
    void shouldGetTypeVerification() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(EvidenceType.VERIFICATION, 30, Collections.emptyList());
        assertEquals(EvidenceType.VERIFICATION, credentialEvidenceItem.getType());
        assertEquals(30, credentialEvidenceItem.getVerificationScore());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotVerification")
    void shouldNotGetTypeVerification(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.VERIFICATION, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotVerification() {
        return Stream.of(
                CredentialEvidenceItem.builder().build(),
                CredentialEvidenceItem.builder()
                        .verificationScore(10)
                        .activityHistoryScore(10)
                        .build(),
                CredentialEvidenceItem.builder()
                        .verificationScore(10)
                        .identityFraudScore(10)
                        .build(),
                CredentialEvidenceItem.builder().verificationScore(10).strengthScore(10).build(),
                CredentialEvidenceItem.builder().verificationScore(10).validityScore(10).build());
    }

    @Test
    void throwsForEvidenceTypeConstructorGetTypeNotActivityIdentityFraudNorVerification() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(EvidenceType.EVIDENCE, 30, Collections.emptyList());
        assertThrows(UnknownEvidenceTypeException.class, credentialEvidenceItem::getType);
    }

    @Test
    void shouldGetTypeEvidence() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                CredentialEvidenceItem.builder().strengthScore(30).validityScore(30).build();
        assertEquals(EvidenceType.EVIDENCE, credentialEvidenceItem.getType());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotEvidence")
    void shouldNotGetTypeEvidence(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.EVIDENCE, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotEvidence() {
        return Stream.of(
                CredentialEvidenceItem.builder().build(),
                CredentialEvidenceItem.builder().strengthScore(10).activityHistoryScore(10).build(),
                CredentialEvidenceItem.builder().validityScore(10).identityFraudScore(10).build(),
                CredentialEvidenceItem.builder().strengthScore(10).verificationScore(10).build(),
                CredentialEvidenceItem.builder()
                        .validityScore(10)
                        .checkDetails(List.of(new CheckDetail()))
                        .build());
    }

    @Test
    void shouldGetTypeDcmaw() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem1 =
                CredentialEvidenceItem.builder()
                        .strengthScore(30)
                        .validityScore(30)
                        .checkDetails(List.of(new CheckDetail()))
                        .failedCheckDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.DCMAW, credentialEvidenceItem1.getType());

        CredentialEvidenceItem credentialEvidenceItem2 =
                CredentialEvidenceItem.builder()
                        .strengthScore(30)
                        .validityScore(30)
                        .failedCheckDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.DCMAW, credentialEvidenceItem2.getType());

        CredentialEvidenceItem credentialEvidenceItem3 =
                CredentialEvidenceItem.builder()
                        .strengthScore(30)
                        .validityScore(30)
                        .checkDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.DCMAW, credentialEvidenceItem3.getType());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotDcmaw")
    void shouldNotGetTypeDcmaw(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.DCMAW, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotDcmaw() {
        return Stream.of(
                CredentialEvidenceItem.builder().build(),
                CredentialEvidenceItem.builder().strengthScore(10).activityHistoryScore(10).build(),
                CredentialEvidenceItem.builder().validityScore(10).identityFraudScore(10).build(),
                CredentialEvidenceItem.builder().strengthScore(10).verificationScore(10).build(),
                CredentialEvidenceItem.builder().validityScore(10).build());
    }

    @Test
    void shouldGetTypeF2F() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem1 =
                CredentialEvidenceItem.builder()
                        .strengthScore(30)
                        .validityScore(30)
                        .verificationScore(30)
                        .checkDetails(List.of(new CheckDetail()))
                        .failedCheckDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.F2F, credentialEvidenceItem1.getType());

        CredentialEvidenceItem credentialEvidenceItem2 =
                CredentialEvidenceItem.builder()
                        .strengthScore(30)
                        .validityScore(30)
                        .verificationScore(30)
                        .checkDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.F2F, credentialEvidenceItem2.getType());

        CredentialEvidenceItem credentialEvidenceItem3 =
                CredentialEvidenceItem.builder()
                        .strengthScore(30)
                        .validityScore(30)
                        .verificationScore(30)
                        .failedCheckDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.F2F, credentialEvidenceItem3.getType());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotF2F")
    void shouldNotGetTypeF2F(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.F2F, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotF2F() {
        return Stream.of(
                CredentialEvidenceItem.builder().build(),
                CredentialEvidenceItem.builder().strengthScore(10).activityHistoryScore(10).build(),
                CredentialEvidenceItem.builder().validityScore(10).identityFraudScore(10).build(),
                CredentialEvidenceItem.builder().verificationScore(10).build(),
                CredentialEvidenceItem.builder().strengthScore(10).validityScore(10).build());
    }

    @Test
    void shouldGetTypeFraudWithActivity() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                CredentialEvidenceItem.builder()
                        .identityFraudScore(30)
                        .activityHistoryScore(30)
                        .build();
        assertEquals(EvidenceType.FRAUD_WITH_ACTIVITY, credentialEvidenceItem.getType());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotFraudWithActivity")
    void shouldNotGetTypeFraudWithActivity(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.FRAUD_WITH_ACTIVITY, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotFraudWithActivity() {
        return Stream.of(
                CredentialEvidenceItem.builder().build(),
                CredentialEvidenceItem.builder().activityHistoryScore(10).strengthScore(10).build(),
                CredentialEvidenceItem.builder()
                        .identityFraudScore(10)
                        .verificationScore(10)
                        .build());
    }

    @Test
    void shouldGetTypeNino() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem1 =
                CredentialEvidenceItem.builder()
                        .checkDetails(List.of(new CheckDetail()))
                        .failedCheckDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.NINO, credentialEvidenceItem1.getType());

        CredentialEvidenceItem credentialEvidenceItem2 =
                CredentialEvidenceItem.builder()
                        .failedCheckDetails(List.of(new CheckDetail()))
                        .build();
        assertEquals(EvidenceType.NINO, credentialEvidenceItem2.getType());

        CredentialEvidenceItem credentialEvidenceItem3 =
                CredentialEvidenceItem.builder().checkDetails(List.of(new CheckDetail())).build();
        assertEquals(EvidenceType.NINO, credentialEvidenceItem3.getType());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForNotNino")
    void shouldNotGetTypeNino(CredentialEvidenceItem item) {
        try {
            assertNotEquals(EvidenceType.NINO, item.getType());
        } catch (UnknownEvidenceTypeException exception) {
            assertThrows(UnknownEvidenceTypeException.class, item::getType);
        }
    }

    private static Stream<CredentialEvidenceItem> provideCasesForNotNino() {
        return Stream.of(
                CredentialEvidenceItem.builder().strengthScore(10).build(),
                CredentialEvidenceItem.builder().validityScore(10).build(),
                CredentialEvidenceItem.builder().verificationScore(10).build(),
                CredentialEvidenceItem.builder().activityHistoryScore(10).build(),
                CredentialEvidenceItem.builder().identityFraudScore(10).build());
    }

    @Test
    void throwsForGetTypeUnknown() {
        CredentialEvidenceItem credentialEvidenceItem = CredentialEvidenceItem.builder().build();
        assertThrows(UnknownEvidenceTypeException.class, credentialEvidenceItem::getType);
    }

    @Test
    void shouldGetEvidenceScore() {
        CredentialEvidenceItem credentialEvidenceItem =
                CredentialEvidenceItem.builder().strengthScore(10).validityScore(20).build();
        assertEquals(new Gpg45Scores.Evidence(10, 20), credentialEvidenceItem.getEvidenceScore());
    }

    @Test
    void shouldHasContraIndicators() {
        CredentialEvidenceItem credentialEvidenceItem1 = new CredentialEvidenceItem(10, 20, null);
        assertFalse(credentialEvidenceItem1.hasContraIndicators());

        CredentialEvidenceItem credentialEvidenceItem2 =
                new CredentialEvidenceItem(10, 20, Collections.emptyList());
        assertFalse(credentialEvidenceItem2.hasContraIndicators());

        CredentialEvidenceItem credentialEvidenceItem3 =
                new CredentialEvidenceItem(10, 20, Arrays.asList("contra1", "contra2"));
        assertTrue(credentialEvidenceItem3.hasContraIndicators());
    }

    @Test
    void shouldSetCredentialIss() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(10, 20, Collections.emptyList());
        credentialEvidenceItem.setCredentialIss("someIss");
        assertEquals("someIss", credentialEvidenceItem.getCredentialIss());
    }
}
