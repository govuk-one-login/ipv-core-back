package uk.gov.di.ipv.core.library.gpg45.domain;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem.EvidenceType;

import java.util.Arrays;
import java.util.Collections;

class CredentialEvidenceItemTest {

    private CredentialEvidenceItem item;

    @Test
    void testConstructorWithEvidenceTypeAndScore() {
        item = new CredentialEvidenceItem(EvidenceType.ACTIVITY, 10, Collections.emptyList());
        assertEquals(10, item.getActivityHistoryScore());
        assertNull(item.getIdentityFraudScore());
        assertNull(item.getVerificationScore());

        item = new CredentialEvidenceItem(EvidenceType.IDENTITY_FRAUD, 20, Collections.emptyList());
        assertNull(item.getActivityHistoryScore());
        assertEquals(20, item.getIdentityFraudScore());
        assertNull(item.getVerificationScore());

        item = new CredentialEvidenceItem(EvidenceType.VERIFICATION, 30, Collections.emptyList());
        assertNull(item.getActivityHistoryScore());
        assertNull(item.getIdentityFraudScore());
        assertEquals(30, item.getVerificationScore());
    }

    @Test
    void testConstructorWithStrengthValidityCi() {
        item = new CredentialEvidenceItem(15, 25, Collections.emptyList());
        assertEquals(15, item.getStrengthScore());
        assertEquals(25, item.getValidityScore());
    }

    @Test
    void testFullArgConstructor() {
        item = new CredentialEvidenceItem(10, 20, 30, 40, Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
        assertEquals(10, item.getStrengthScore());
        assertEquals(20, item.getValidityScore());
        assertEquals(30, item.getActivityHistoryScore());
        assertEquals(40, item.getVerificationScore());
    }

    @Test
    void testGetEvidenceScore() {
        item = new CredentialEvidenceItem(10, 20, Collections.emptyList());
        assertEquals(10, item.getStrengthScore());
        assertEquals(20, item.getValidityScore());
    }

    @Test
    void testHasContraIndicators() {
        item = new CredentialEvidenceItem(10, 20, null);
        assertFalse(item.hasContraIndicators());

        item = new CredentialEvidenceItem(10, 20, Collections.emptyList());
        assertFalse(item.hasContraIndicators());

        item = new CredentialEvidenceItem(10, 20, Arrays.asList("contra1", "contra2"));
        assertTrue(item.hasContraIndicators());
    }

    @Test
    void testSetCredentialIss() {
        item = new CredentialEvidenceItem(10, 20, Collections.emptyList());
        item.setCredentialIss("someIss");
        assertEquals("someIss", item.getCredentialIss());
    }
}
