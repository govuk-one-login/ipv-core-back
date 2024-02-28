package uk.gov.di.ipv.core.library.auditing.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedDataForAuditEvent;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitMissingDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitNonDcmaw;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fBrp;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportNonDcmawSuccessful;

@ExtendWith(MockitoExtension.class)
class AuditExtensionsHelperTest {
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldGetVerifiableCredentialExtensionsForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcPassportNonDcmawSuccessful());
        var auditExtensions = getExtensionsForAudit(testVerifiableCredential, false);
        assertFalse(auditExtensions.getSuccessful());
        assertTrue(auditExtensions.getIsUkIssued());
        assertEquals(58, auditExtensions.getAge());
        assertEquals("https://review-p.staging.account.gov.uk", auditExtensions.getIss());
        assertEquals(2, auditExtensions.getEvidence().get(0).get("validityScore").asInt());
        assertEquals(4, auditExtensions.getEvidence().get(0).get("strengthScore").asInt());
        assertEquals(
                "1c04edf0-a205-4585-8877-be6bd1776a39",
                auditExtensions.getEvidence().get(0).get("txn").asText());
        assertEquals(
                2,
                auditExtensions
                        .getEvidence()
                        .get(0)
                        .get("checkDetails")
                        .findValues("dataCheck")
                        .size());
    }

    @Test
    void shouldGetPassportRestrictedDataForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcPassportNonDcmawSuccessful());
        var restrictedData = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"KENNETH\"},{\"type\":\"FamilyName\",\"value\":\"DECERQUEIRA\"}]}],\"docExpiryDate\":\"2030-01-01\"}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetDLRestrictedDataForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcDrivingPermitNonDcmaw());
        var restrictedData = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"Alice\"},{\"type\":\"GivenName\",\"value\":\"Jane\"},{\"type\":\"FamilyName\",\"value\":\"Parker\"}]}],\"docExpiryDate\":\"2032-02-02\"}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetRestrictedDataWithoutDocForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcAddressTwo());
        var restrictedData = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"Alice\"},{\"type\":\"GivenName\",\"value\":\"Jane\"},{\"type\":\"FamilyName\",\"value\":\"Parker\"}]}],\"docExpiryDate\":null}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetPassportExpiryDateForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcPassportNonDcmawSuccessful());
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals("2030-01-01", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldNotGetExpiryDateForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcDrivingPermitMissingDrivingPermit());
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertNull(auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetBRPExpiryDateForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcF2fBrp());
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals("2030-07-13", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetIdCardExpiryDateForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(vcF2fIdCard());
        var auditNameParts = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals("2031-08-02", auditNameParts.getDocExpiryDate());
    }
}
