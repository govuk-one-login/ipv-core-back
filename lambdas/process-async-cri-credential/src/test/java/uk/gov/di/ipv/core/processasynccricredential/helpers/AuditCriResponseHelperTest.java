package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AuditCriResponseHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AuditCriResponseHelper.getVcNamePartsForAudit;

@ExtendWith(MockitoExtension.class)
class AuditCriResponseHelperTest {

    @Test
    void shouldGetVerifiableCredentialExtensionsForAudit()
            throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(SIGNED_VC_1);
        var auditExtensions = getExtensionsForAudit(testVerifiableCredential, false);
        assertFalse(auditExtensions.isSuccessful());
        assertEquals("test-issuer", auditExtensions.getIss());
        assertEquals(
                "[{\"validityScore\":2,\"strengthScore\":4,\"ci\":null,\"txn\":\"1e0f28c5-6329-46f0-bf0e-833cb9b58c9e\",\"type\":\"IdentityCheck\"}]",
                auditExtensions.getEvidence().toString());
    }

    @Test
    void shouldGetVerifiableCredentialNamePartsForAudit()
            throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(SIGNED_VC_1);
        var auditNameParts = getVcNamePartsForAudit(testVerifiableCredential);
        assertEquals(
                "[{\"type\":\"GivenName\",\"value\":\"Paul\"}]",
                auditNameParts.getNameParts().toString());
    }
}
