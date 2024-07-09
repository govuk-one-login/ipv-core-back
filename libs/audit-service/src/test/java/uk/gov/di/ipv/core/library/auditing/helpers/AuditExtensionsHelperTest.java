package uk.gov.di.ipv.core.library.auditing.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.TestVc;
import uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator;
import uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator;
import uk.gov.di.ipv.core.library.helpers.vocab.SocialSecurityRecordDetailsGenerator;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.RiskAssessment;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForF2F;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForInheritedIdentity;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitMissingDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitNoCredentialSubjectProperty;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitNonDcmaw;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fBrp;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;

@ExtendWith(MockitoExtension.class)
class AuditExtensionsHelperTest {
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldGetIdentityCheckVerifiableCredentialExtensionsForAudit() throws Exception {
        var auditExtensions =
                (AuditExtensionsVcEvidence<IdentityCheck>)
                        getExtensionsForAudit(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, false);
        var expectedAge =
                Period.between(LocalDate.parse(TestVc.DEFAULT_DOB), LocalDate.now()).getYears();
        assertFalse(auditExtensions.successful());
        assertTrue(auditExtensions.isUkIssued());
        assertEquals(expectedAge, auditExtensions.age());
        assertEquals("https://review-p.staging.account.gov.uk", auditExtensions.iss());
        assertEquals(2, auditExtensions.evidence().get(0).getValidityScore());
        assertEquals(4, auditExtensions.evidence().get(0).getStrengthScore());
        assertEquals(
                "1c04edf0-a205-4585-8877-be6bd1776a39", auditExtensions.evidence().get(0).getTxn());
        assertEquals(
                2,
                auditExtensions.evidence().get(0).getCheckDetails().stream()
                        .filter(checkDetail -> checkDetail.getDataCheck() != null)
                        .count());
    }

    @Test
    void shouldGetRiskAssessmentVerifiableCredentialExtensionsForAudit() throws Exception {
        var auditExtensions =
                (AuditExtensionsVcEvidence<RiskAssessment>) getExtensionsForAudit(vcTicf(), false);
        assertFalse(auditExtensions.successful());
        assertNull(auditExtensions.isUkIssued());
        assertNull(auditExtensions.age());
        assertEquals("https://ticf.stubs.account.gov.uk", auditExtensions.iss());
        assertEquals(
                "963deeb5-a52c-4030-a69a-3184f77a4f18", auditExtensions.evidence().get(0).getTxn());
    }

    @Test
    void shouldGetPassportRestrictedDataForAudit() throws Exception {
        var restrictedData = getRestrictedAuditDataForF2F(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
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
    void shouldGetDLRestrictedDataForAudit() throws Exception {
        var restrictedData = getRestrictedAuditDataForF2F(vcDrivingPermitNonDcmaw());
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
    void getRestrictedAuditDataForF2FShouldReturnEmptyAuditRestrictedF2fIfInvalidVcType()
            throws Exception {
        var restricted = getRestrictedAuditDataForF2F(VC_ADDRESS);

        assertNull(restricted.getName());
        assertNull(restricted.getDocExpiryDate());
    }

    @Test
    void getRestrictedAuditDataForF2FShouldThrowIfNullCredentialSubject() {
        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                getRestrictedAuditDataForF2F(
                                        vcDrivingPermitNoCredentialSubjectProperty()));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(ErrorResponse.CREDENTIAL_SUBJECT_MISSING, thrownException.getErrorResponse());
    }

    @Test
    void getAuditRestrictedInheritedIdentityShouldReturnTheRightStuff() throws Exception {
        var restricted =
                getRestrictedAuditDataForInheritedIdentity(vcHmrcMigration(), "test_device_data");

        var expectedName =
                List.of(
                        NameGenerator.createName(
                                List.of(
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "KENNETH", NamePart.NamePartType.GIVEN_NAME),
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "DECERQUEIRA",
                                                NamePart.NamePartType.FAMILY_NAME))));
        var expectedBirthDate = List.of(BirthDateGenerator.createBirthDate("1965-07-08"));
        var expectedSocialSecurityRecord =
                List.of(
                        SocialSecurityRecordDetailsGenerator.createSocialSecurityRecordDetails(
                                "AB123456C")); // pragma: allowlist secret
        assertEquals(expectedName, restricted.name());
        assertEquals(expectedBirthDate, restricted.birthDate());
        assertEquals(expectedSocialSecurityRecord, restricted.socialSecurityRecord());
        assertEquals(
                "{\"encoded\":\"test_device_data\"}",
                OBJECT_MAPPER.writeValueAsString(restricted.deviceInformation()));
    }

    @Test
    void getRestrictedAuditDataForInheritedIdentityShouldThrowIfInvalidVcType() {
        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                getRestrictedAuditDataForInheritedIdentity(
                                        VC_ADDRESS, "test-device-info"));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(ErrorResponse.UNEXPECTED_CREDENTIAL_TYPE, thrownException.getErrorResponse());
    }

    @Test
    void getRestrictedAuditDataForInheritedIdentityShouldThrowIfMissingCredentialSubject() {
        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                getRestrictedAuditDataForInheritedIdentity(
                                        vcDrivingPermitNoCredentialSubjectProperty(),
                                        "test-device-info"));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(ErrorResponse.CREDENTIAL_SUBJECT_MISSING, thrownException.getErrorResponse());
    }
}
