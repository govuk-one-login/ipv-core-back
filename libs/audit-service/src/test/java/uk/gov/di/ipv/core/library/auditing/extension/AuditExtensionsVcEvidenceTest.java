package uk.gov.di.ipv.core.library.auditing.extension;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;

class AuditExtensionsVcEvidenceTest {

    @Test
    void shouldInitWithNullEvidence() {
        var auditExtensions =
                new AuditExtensionsVcEvidence(
                        "http://issuer.example.com", null, false, null, null, null, null);
        assertNull(auditExtensions.evidence());
    }
}
