package uk.gov.di.ipv.core.library.auditing.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;

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
    private static String VC_PASSPORT_NON_DCMAW_SUCCESSFUL;
    private static String VC_ADDRESS_2;
    private static String VC_DRIVING_PERMIT_DCMAW_MISSING_DRIVING_PERMIT_PROPERTY;
    private static String VC_DRIVING_PERMIT_NON_DCMAW;
    private static String F2F_BRP_VC;
    private static String F2F_ID_CARD_VC;
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeAll
    static void setUp() throws Exception {
        VC_PASSPORT_NON_DCMAW_SUCCESSFUL = vcPassportNonDcmawSuccessful();
        VC_ADDRESS_2 = vcAddressTwo();
        VC_DRIVING_PERMIT_DCMAW_MISSING_DRIVING_PERMIT_PROPERTY =
                vcDrivingPermitMissingDrivingPermit();
        VC_DRIVING_PERMIT_NON_DCMAW = vcDrivingPermitNonDcmaw();
        F2F_BRP_VC = vcF2fBrp();
        F2F_ID_CARD_VC = vcF2fIdCard();
    }

    @Test
    void shouldGetVerifiableCredentialExtensionsForAudit() throws Exception {
        SignedJWT testVerifiableCredential = SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL);
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
    void shouldGetPassportRestrictedDataForAudit() throws ParseException, JsonProcessingException {
        SignedJWT testVerifiableCredential = SignedJWT.parse(VC_PASSPORT_NON_DCMAW_SUCCESSFUL);
        var restrictedData = getRestrictedDataForAuditEvent(testVerifiableCredential);
        assertEquals(
                "{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"KENNETH\"},{\"type\":\"FamilyName\",\"value\":\"DECERQUEIRA\"}]}],\"docExpiryDate\":\"2030-01-01\"}",
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
        assertEquals("2030-01-01", auditNameParts.getDocExpiryDate());
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
