package uk.gov.di.ipv.core.library.gpg45.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem.EvidenceType;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialEvidenceItemTest {
    @ParameterizedTest
    @MethodSource("provideCasesForConstructorWithEvidenceTypeAndScore")
    void shouldConstructorWithEvidenceTypeAndScore(EvidenceType evidenceType) {
        Random rand = new Random();
        int score = rand.nextInt(10, 40);
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(evidenceType, score, Collections.emptyList());

        switch (evidenceType) {
            case ACTIVITY -> {
                assertEquals(score, credentialEvidenceItem.getActivityHistoryScore());
                assertNull(credentialEvidenceItem.getIdentityFraudScore());
                assertNull(credentialEvidenceItem.getVerificationScore());
            }
            case IDENTITY_FRAUD -> {
                assertNull(credentialEvidenceItem.getActivityHistoryScore());
                assertEquals(score, credentialEvidenceItem.getIdentityFraudScore());
                assertNull(credentialEvidenceItem.getVerificationScore());
            }
            case VERIFICATION -> {
                assertNull(credentialEvidenceItem.getActivityHistoryScore());
                assertNull(credentialEvidenceItem.getIdentityFraudScore());
                assertEquals(score, credentialEvidenceItem.getVerificationScore());
            }
        }
    }

    private static Stream<EvidenceType> provideCasesForConstructorWithEvidenceTypeAndScore() {
        return Stream.of(
                EvidenceType.ACTIVITY, EvidenceType.IDENTITY_FRAUD, EvidenceType.VERIFICATION);
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
                CredentialEvidenceItem.builder().activityHistoryScore(30).build();
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
    void shouldHaveContraIndicators() {
        CredentialEvidenceItem credentialEvidenceItem1 =
                CredentialEvidenceItem.builder().strengthScore(10).validityScore(20).build();
        assertFalse(credentialEvidenceItem1.hasContraIndicators());

        CredentialEvidenceItem credentialEvidenceItem2 =
                CredentialEvidenceItem.builder()
                        .strengthScore(10)
                        .validityScore(20)
                        .ci(Collections.emptyList())
                        .build();
        assertFalse(credentialEvidenceItem2.hasContraIndicators());

        CredentialEvidenceItem credentialEvidenceItem3 =
                CredentialEvidenceItem.builder()
                        .strengthScore(10)
                        .validityScore(20)
                        .ci(Arrays.asList("contra1", "contra2"))
                        .build();
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
