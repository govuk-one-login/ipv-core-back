package uk.gov.di.ipv.core.library.auditing.extension;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.exceptions.AuditExtensionException;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuditExtensionsVcEvidenceTest {

    @Test
    void shouldInitWithNullEvidence() throws AuditExtensionException {
        var auditExtensions =
                new AuditExtensionsVcEvidence(
                        "http://issuer.example.com", null, false, null, null, null);
        assertNull(auditExtensions.getEvidence());
    }

    @Test
    void shouldInitWithoutVotIsUkIssuedAndAge() throws AuditExtensionException {
        var auditExtensions =
                new AuditExtensionsVcEvidence("http://issuer.example.com", null, false);
        assertNull(auditExtensions.getVot());
        assertNull(auditExtensions.getIsUkIssued());
        assertNull(auditExtensions.getAge());
    }

    @Test
    void shouldNotInitWithInvalidEvidence() {

        assertThrows(
                AuditExtensionException.class,
                () ->
                        new AuditExtensionsVcEvidence(
                                "http://issuer.example.com",
                                "invalid-evidence",
                                false,
                                null,
                                null,
                                null));
    }
}
