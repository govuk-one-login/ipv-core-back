package uk.gov.di.ipv.core.processasynccricredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.F2F_BRP_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.F2F_ID_CARD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_ADDRESS_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_DRIVING_PERMIT_DCMAW_MISSING_DRIVING_PERMIT_PROPERTY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_DRIVING_PERMIT_NON_DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL_WITH_ICAOCODE;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AuditCriResponseHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AuditCriResponseHelper.getRestrictedDataForAuditEvent;

@ExtendWith(MockitoExtension.class)
class AuditCriResponseHelperTest {

    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldGetVerifiableCredentialExtensionsForAudit()
            throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL);
        var auditExtensions = getExtensionsForAudit(testVerifiableCredential, false, PASSPORT_CRI);
        assertFalse(auditExtensions.getSuccessful());
        assertEquals("test-issuer", auditExtensions.getIss());
        assertEquals(
                "[{\"validityScore\":2,\"strengthScore\":4,\"ci\":null,\"txn\":\"1e0f28c5-6329-46f0-bf0e-833cb9b58c9e\",\"type\":\"IdentityCheck\"}]",
                auditExtensions.getEvidence().toString());
        assertEquals(
                "{\"iss\":\"test-issuer\",\"evidence\":[{\"validityScore\":2,\"strengthScore\":4,\"ci\":null,\"txn\":\"1e0f28c5-6329-46f0-bf0e-833cb9b58c9e\",\"type\":\"IdentityCheck\"}],\"successful\":false,\"age\":4}",
                OBJECT_MAPPER.writeValueAsString(auditExtensions));
        assertNotNull(auditExtensions.getAge());
        assertNull(auditExtensions.getIsUkIssued());
    }

    @Test
    void shouldGetVerifiableCredentialExtensionsForAuditWithICAOCode()
            throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential =
                SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL_WITH_ICAOCODE);
        var auditExtensions = getExtensionsForAudit(testVerifiableCredential, false, PASSPORT_CRI);
        assertEquals(
                "{\"iss\":\"https://review-p.staging.account.gov.uk\",\"evidence\":[{\"checkDetails\":[{\"checkMethod\":\"data\",\"dataCheck\":\"cancelled_check\"},{\"checkMethod\":\"data\",\"dataCheck\":\"record_check\"}],\"validityScore\":2,\"strengthScore\":4,\"ci\":[],\"txn\":\"1c04edf0-a205-4585-8877-be6bd1776a39\",\"type\":\"IdentityCheck\",\"ciReasons\":[]}],\"successful\":false,\"isUkIssued\":true,\"age\":58}",
                OBJECT_MAPPER.writeValueAsString(auditExtensions));
        assertNotNull(auditExtensions.getAge());
        assertTrue(auditExtensions.getIsUkIssued());
    }

    @Test
    void shouldGetPassportRestrictedDataForAudit() throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL);
        var restrictedData = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"Paul\"}]}],\"docExpiryDate\":\"2020-01-01\"}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetDLRestrictedDataForAudit() throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(VC_DRIVING_PERMIT_NON_DCMAW);
        var restrictedData = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"Alice\"},{\"type\":\"GivenName\",\"value\":\"Jane\"},{\"type\":\"FamilyName\",\"value\":\"Parker\"}]}],\"docExpiryDate\":\"2032-02-02\"}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetRestrictedDataWithoutDocForAudit()
            throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(VC_ADDRESS_2);
        var restrictedData = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"Alice\"},{\"type\":\"GivenName\",\"value\":\"Jane\"},{\"type\":\"FamilyName\",\"value\":\"Parker\"}]}],\"docExpiryDate\":null}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetPassportExpiryDateForAudit() throws ParseException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL);
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals("2020-01-01", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldNotGetExpiryDateForAudit() throws ParseException {
        SignedJWT testVerifiableCredential =
                SignedJWT.parse(VC_DRIVING_PERMIT_DCMAW_MISSING_DRIVING_PERMIT_PROPERTY);
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertNull(auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetBRPExpiryDateForAudit() throws ParseException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(F2F_BRP_VC);
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals("2030-07-13", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetIdCardExpiryDateForAudit() throws ParseException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(F2F_ID_CARD_VC);
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals("2031-08-02", auditNameParts.getDocExpiryDate());
    }
}
