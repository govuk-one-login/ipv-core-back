package uk.gov.di.ipv.core.library.gpg45.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.exceptions.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem.EvidenceType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialEvidenceItemTest {
    @Test
    void testConstructorWithEvidenceTypeAndScore() {
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
    void testConstructorWithStrengthValidityCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(15, 25, Collections.emptyList());
        assertEquals(15, credentialEvidenceItem.getStrengthScore());
        assertEquals(25, credentialEvidenceItem.getValidityScore());
    }

    @Test
    void testFullArgConstructor() {
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
    void testGetTypeActivity() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(EvidenceType.ACTIVITY, 30, Collections.emptyList());
        assertEquals(EvidenceType.ACTIVITY, credentialEvidenceItem.getType());
        assertEquals(30, credentialEvidenceItem.getActivityHistoryScore());
    }

    @Test
    void testGetTypeIdentityFraud() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        EvidenceType.IDENTITY_FRAUD, 30, Collections.emptyList());
        assertEquals(EvidenceType.IDENTITY_FRAUD, credentialEvidenceItem.getType());
        assertEquals(30, credentialEvidenceItem.getIdentityFraudScore());
    }

    @Test
    void testGetTypeVerification() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(EvidenceType.VERIFICATION, 30, Collections.emptyList());
        assertEquals(EvidenceType.VERIFICATION, credentialEvidenceItem.getType());
        assertEquals(30, credentialEvidenceItem.getVerificationScore());
    }

    @Test
    void testGetTypeEvidence() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                CredentialEvidenceItem.builder().strengthScore(30).validityScore(30).build();
        assertEquals(EvidenceType.EVIDENCE, credentialEvidenceItem.getType());
    }

    @Test
    void testIsDcmaw() throws UnknownEvidenceTypeException {
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

    @Test
    void testIsF2F() throws UnknownEvidenceTypeException {
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

    @Test
    void testIsFraudWithActivity() throws UnknownEvidenceTypeException {
        CredentialEvidenceItem credentialEvidenceItem =
                CredentialEvidenceItem.builder()
                        .identityFraudScore(30)
                        .activityHistoryScore(30)
                        .build();
        assertEquals(EvidenceType.FRAUD_WITH_ACTIVITY, credentialEvidenceItem.getType());
    }

    @Test
    void testIsNino() throws UnknownEvidenceTypeException {
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

    @Test
    void testGetTypeUnknown() {
        CredentialEvidenceItem credentialEvidenceItem = CredentialEvidenceItem.builder().build();
        assertThrows(UnknownEvidenceTypeException.class, credentialEvidenceItem::getType);
    }

    @Test
    void testHasContraIndicators() {
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
    void testSetCredentialIss() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(10, 20, Collections.emptyList());
        credentialEvidenceItem.setCredentialIss("someIss");
        assertEquals("someIss", credentialEvidenceItem.getCredentialIss());
    }
}
