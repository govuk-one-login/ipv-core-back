package uk.gov.di.ipv.core.library.auditing.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.fixtures.VcFixtures;
import uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.RiskAssessment;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAuditWithCriId;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForAsync;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsyncPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fBrp;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvlaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitMissingDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitNoCredentialSubjectProperty;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;

@ExtendWith(MockitoExtension.class)
class AuditExtensionsHelperTest {
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldGetIdentityCheckVerifiableCredentialExtensionsForAudit() throws Exception {
        var auditExtensions = getExtensionsForAudit(vcWebPassportSuccessful(), false);
        var evidence = (IdentityCheck) auditExtensions.evidence().get(0);

        var expectedAge =
                Period.between(LocalDate.parse(VcFixtures.DEFAULT_DOB), LocalDate.now()).getYears();
        assertFalse(auditExtensions.successful());
        assertTrue(auditExtensions.isUkIssued());
        assertEquals(expectedAge, auditExtensions.age());
        assertEquals("https://review-p.staging.account.gov.uk", auditExtensions.iss());
        assertEquals(2, evidence.getValidityScore());
        assertEquals(4, evidence.getStrengthScore());
        assertEquals("1c04edf0-a205-4585-8877-be6bd1776a39", evidence.getTxn());
        assertEquals(1, evidence.getCheckDetails().size());
    }

    @Test
    void shouldGetIdentityCheckVerifiableCredentialExtensionsForAsyncAudit() throws Exception {
        var auditExtensions = getExtensionsForAuditWithCriId(vcDcmawAsyncPassport(), false);
        var evidence = (IdentityCheck) auditExtensions.evidence().get(0);

        var expectedAge =
                Period.between(LocalDate.parse(VcFixtures.DEFAULT_DOB), LocalDate.now()).getYears();
        assertFalse(auditExtensions.successful());
        assertTrue(auditExtensions.isUkIssued());
        assertEquals("dcmawAsync", auditExtensions.credential_issuer_id());
        assertEquals(expectedAge, auditExtensions.age());
        assertEquals(
                "https://dcmaw-async.stubs.account.gov.uk/async/credential", auditExtensions.iss());
        assertEquals(2, evidence.getValidityScore());
        assertEquals(4, evidence.getStrengthScore());
        assertEquals("bcd2346", evidence.getTxn());
    }

    @Test
    void shouldGetRiskAssessmentVerifiableCredentialExtensionsForAudit() throws Exception {
        var auditExtensions = getExtensionsForAudit(vcTicf(), false);
        var evidence = (RiskAssessment) auditExtensions.evidence().get(0);

        assertFalse(auditExtensions.successful());
        assertNull(auditExtensions.isUkIssued());
        assertNull(auditExtensions.age());
        assertEquals("https://ticf.stubs.account.gov.uk", auditExtensions.iss());
        assertEquals("963deeb5-a52c-4030-a69a-3184f77a4f18", evidence.getTxn());
    }

    @Test
    void shouldGetPassportRestrictedDataForAudit() {
        var restrictedData = getRestrictedAuditDataForAsync(vcWebPassportSuccessful());
        var expectedName =
                List.of(
                        NameGenerator.createName(
                                List.of(
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "KENNETH", NamePart.NamePartType.GIVEN_NAME),
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "DECERQUEIRA",
                                                NamePart.NamePartType.FAMILY_NAME))));

        assertEquals(expectedName, restrictedData.getName());
        assertEquals("2030-01-01", restrictedData.getDocExpiryDate());
    }

    @Test
    void shouldGetDLRestrictedDataForAudit() {
        var restrictedData = getRestrictedAuditDataForAsync(vcWebDrivingPermitDvlaValid());
        var expectedName =
                List.of(
                        NameGenerator.createName(
                                List.of(
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "Alice", NamePart.NamePartType.GIVEN_NAME),
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "Jane", NamePart.NamePartType.GIVEN_NAME),
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "Parker", NamePart.NamePartType.FAMILY_NAME))));

        assertEquals(expectedName, restrictedData.getName());
        assertEquals("2032-02-02", restrictedData.getDocExpiryDate());
    }

    @Test
    void shouldGetPassportExpiryDateForAudit() {
        var auditNameParts = getRestrictedAuditDataForAsync(vcWebPassportSuccessful());
        assertEquals("2030-01-01", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldNotGetExpiryDateForAudit() {
        var auditNameParts =
                getRestrictedAuditDataForAsync(vcWebDrivingPermitMissingDrivingPermit());
        assertNull(auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetBRPExpiryDateForAudit() {
        var auditNameParts = getRestrictedAuditDataForAsync(vcF2fBrp());
        assertEquals("2030-07-13", auditNameParts.getDocExpiryDate());
    }

    @Test
    void shouldGetIdCardExpiryDateForAudit() {
        var auditNameParts = getRestrictedAuditDataForAsync(vcF2fIdCard());
        assertEquals("2031-08-02", auditNameParts.getDocExpiryDate());
    }

    @Test
    void getRestrictedAuditDataForAsyncShouldReturnEmptyAuditRestrictedAsyncIfInvalidVcType() {
        var restricted = getRestrictedAuditDataForAsync(vcAddressOne());

        assertNull(restricted.getName());
        assertNull(restricted.getDocExpiryDate());
    }

    @Test
    void getRestrictedAuditDataForAsyncShouldNullValuesIfNullCredentialSubject() {
        var restricted =
                getRestrictedAuditDataForAsync(vcWebDrivingPermitNoCredentialSubjectProperty());

        assertNull(restricted.getName());
        assertNull(restricted.getDocExpiryDate());
    }
}
