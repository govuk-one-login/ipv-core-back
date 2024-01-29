package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;

class AuditExtensionsReceivedVcEvidenceTest {

    @Test
    void shouldInitWithNullEvidence() throws JsonProcessingException {
        var auditExtensions =
                new AuditExtensionsReceivedVcEvidence("http://issuer.example.com", null, false);
        assertNull(auditExtensions.getEvidence());
    }
}
