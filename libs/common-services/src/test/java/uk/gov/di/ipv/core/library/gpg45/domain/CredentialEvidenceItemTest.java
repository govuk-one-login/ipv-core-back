package uk.gov.di.ipv.core.library.gpg45.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem.EvidenceType;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

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
    void testGetEvidenceScore() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(10, 20, Collections.emptyList());
        assertEquals(10, credentialEvidenceItem.getStrengthScore());
        assertEquals(20, credentialEvidenceItem.getValidityScore());
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
