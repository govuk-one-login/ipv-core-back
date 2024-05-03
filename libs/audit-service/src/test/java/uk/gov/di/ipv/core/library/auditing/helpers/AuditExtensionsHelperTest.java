package uk.gov.di.ipv.core.library.auditing.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForF2F;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForInheritedIdentity;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitMissingDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitNonDcmaw;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fBrp;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;

@ExtendWith(MockitoExtension.class)
class AuditExtensionsHelperTest {
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldGetVerifiableCredentialExtensionsForAudit() throws Exception {
        var auditExtensions = getExtensionsForAudit(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, false);
        assertFalse(auditExtensions.successful());
        assertTrue(auditExtensions.isUkIssued());
        assertEquals(58, auditExtensions.age());
        assertEquals("https://review-p.staging.account.gov.uk", auditExtensions.iss());
        assertEquals(2, auditExtensions.evidence().get(0).get("validityScore").asInt());
        assertEquals(4, auditExtensions.evidence().get(0).get("strengthScore").asInt());
        assertEquals(
                "1c04edf0-a205-4585-8877-be6bd1776a39",
                auditExtensions.evidence().get(0).get("txn").asText());
        assertEquals(
                2,
                auditExtensions
                        .evidence()
                        .get(0)
                        .get("checkDetails")
                        .findValues("dataCheck")
                        .size());
    }

    @Test
    void shouldGetPassportRestrictedDataForAudit() throws Exception {
        var restrictedData = getRestrictedAuditDataForF2F(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"value\":\"KENNETH\",\"type\":\"GivenName\"},{\"value\":\"DECERQUEIRA\",\"type\":\"FamilyName\"}]}],\"docExpiryDate\":\"2030-01-01\"}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetDLRestrictedDataForAudit() throws Exception {
        var restrictedData = getRestrictedAuditDataForF2F(vcDrivingPermitNonDcmaw());
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"value\":\"Alice\",\"type\":\"GivenName\"},{\"value\":\"Jane\",\"type\":\"GivenName\"},{\"value\":\"Parker\",\"type\":\"FamilyName\"}]}],\"docExpiryDate\":\"2032-02-02\"}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetRestrictedDataWithoutDocForAudit() throws Exception {
        var restrictedData = getRestrictedAuditDataForF2F(vcAddressTwo());
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"value\":\"Alice\",\"type\":\"GivenName\"},{\"value\":\"Jane\",\"type\":\"GivenName\"},{\"value\":\"Parker\",\"type\":\"FamilyName\"}]}],\"docExpiryDate\":null}",
                OBJECT_MAPPER.writeValueAsString(restrictedData));
    }

    @Test
    void shouldGetPassportExpiryDateForAudit() throws Exception {
        var auditNameParts = getRestrictedAuditDataForF2F(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        assertEquals("2030-01-01", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldNotGetExpiryDateForAudit() throws Exception {
        var auditNameParts = getRestrictedAuditDataForF2F(vcDrivingPermitMissingDrivingPermit());
        assertNull(auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetBRPExpiryDateForAudit() throws Exception {
        var auditNameParts = getRestrictedAuditDataForF2F(vcF2fBrp());
        assertEquals("2030-07-13", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetIdCardExpiryDateForAudit() throws Exception {
        var auditNameParts = getRestrictedAuditDataForF2F(vcF2fIdCard());
        assertEquals("2031-08-02", auditNameParts.getDocExpiryDate());
    }

    @Test
    void getAuditRestrictedInheritedIdentityShouldReturnTheRightStuff() throws Exception {
        var restricted =
                getRestrictedAuditDataForInheritedIdentity(vcHmrcMigration(), "test_device_data");

        assertEquals(
                "[{\"nameParts\":[{\"value\":\"KENNETH\",\"type\":\"GivenName\"},{\"value\":\"DECERQUEIRA\",\"type\":\"FamilyName\"}]}]",
                OBJECT_MAPPER.writeValueAsString(restricted.name()));
        assertEquals(
                "[{\"value\":\"1965-07-08\"}]",
                OBJECT_MAPPER.writeValueAsString(restricted.birthDate()));
        assertEquals(
                "[{\"personalNumber\":\"AB123456C\"}]",
                OBJECT_MAPPER.writeValueAsString(restricted.socialSecurityRecord()));
        assertEquals(
                "{\"encoded\":\"test_device_data\"}",
                OBJECT_MAPPER.writeValueAsString(restricted.deviceInformation()));
    }
}
