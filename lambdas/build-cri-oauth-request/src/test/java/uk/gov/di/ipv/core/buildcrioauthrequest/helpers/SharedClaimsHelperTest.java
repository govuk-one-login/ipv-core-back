package uk.gov.di.ipv.core.buildcrioauthrequest.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.Name;
import uk.gov.di.model.SocialSecurityRecordDetails;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper.SHARED_CLAIM_ATTR_ADDRESS;
import static uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper.SHARED_CLAIM_ATTR_BIRTH_DATE;
import static uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper.SHARED_CLAIM_ATTR_DRIVING_PERMIT;
import static uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper.SHARED_CLAIM_ATTR_EMAIL;
import static uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper.SHARED_CLAIM_ATTR_NAME;
import static uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper.SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD;
import static uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper.generateSharedClaims;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.ADDRESS_1;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.ADDRESS_2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.TEST_SUBJECT;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcClaimDcmawPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawPassport;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator.createBirthDate;
import static uk.gov.di.ipv.core.library.helpers.vocab.DrivingPermitDetailsGenerator.createDrivingPermitDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.createName;
import static uk.gov.di.ipv.core.library.helpers.vocab.SocialSecurityRecordDetailsGenerator.createSocialSecurityRecordDetails;

class SharedClaimsHelperTest {
    private static final List<String> ALL_ATTRIBUTES =
            List.of(
                    SHARED_CLAIM_ATTR_NAME,
                    SHARED_CLAIM_ATTR_BIRTH_DATE,
                    SHARED_CLAIM_ATTR_ADDRESS,
                    SHARED_CLAIM_ATTR_EMAIL,
                    SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD,
                    SHARED_CLAIM_ATTR_DRIVING_PERMIT);

    private static final Cri TEST_CRI = Cri.DCMAW;

    private static final String TEST_EMAIL = "test@example.com";
    private static final Name TEST_NAME = createName("Test", "User");
    private static final BirthDate TEST_DOB = createBirthDate("1970-01-01");
    private static final SocialSecurityRecordDetails TEST_NINO =
            createSocialSecurityRecordDetails("test-nino");
    private static final DrivingPermitDetails TEST_DRIVING_PERMIT =
            createDrivingPermitDetails("TESTU710112PBFGA", "2062-02-02", "ISSUER", "2005-02-02");

    @Test
    void generatesSharedClaimsForAllSupportedAttributes() {
        var vcs =
                List.of(
                        vcAddressOne(),
                        generateIdentityVc(
                                IdentityCheckSubject.builder()
                                        .withName(List.of(TEST_NAME))
                                        .withBirthDate(List.of(TEST_DOB))
                                        .withSocialSecurityRecord(List.of(TEST_NINO))
                                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                                        .build()));

        var sharedClaims = generateSharedClaims(TEST_EMAIL, vcs, ALL_ATTRIBUTES, TEST_CRI);

        assertEquals(TEST_EMAIL, sharedClaims.getEmailAddress());
        assertEquals(Set.of(TEST_NAME), sharedClaims.getName());
        assertEquals(Set.of(TEST_DOB), sharedClaims.getBirthDate());
        assertEquals(Set.of(ADDRESS_1), sharedClaims.getAddress());
        assertEquals(Set.of(TEST_NINO), sharedClaims.getSocialSecurityRecord());
        assertEquals(Set.of(TEST_DRIVING_PERMIT), sharedClaims.getDrivingPermit());
    }

    private static IdentityCheckSubject.IdentityCheckSubjectBuilderBase
            getDlCredentialSubjectBuilder() {
        return IdentityCheckSubject.builder()
                .withName(List.of(TEST_NAME))
                .withBirthDate(List.of(TEST_DOB))
                .withSocialSecurityRecord(List.of(TEST_NINO));
    }

    @Test
    void
            generatesSharedClaimsShouldNotReturnDrivingPermitSharedClaimFromDrivingLicenceIfTargetCriIsDrivingLicence() {
        var updatedTestDrivingPermit =
                createDrivingPermitDetails("another-number", "2062-02-02", "ISSUER", "2005-02-02");

        var anotherDrivingPermit =
                createDrivingPermitDetails("another-number1", "2062-02-02", "ISSUER", "2005-02-02");
        var vcs =
                List.of(
                        generateIdentityVc(
                                getDlCredentialSubjectBuilder()
                                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                                        .build(),
                                Cri.DRIVING_LICENCE),
                        generateIdentityVc(
                                getDlCredentialSubjectBuilder()
                                        .withDrivingPermit(List.of(updatedTestDrivingPermit))
                                        .build(),
                                Cri.DCMAW),
                        generateIdentityVc(
                                getDlCredentialSubjectBuilder()
                                        .withDrivingPermit(List.of(anotherDrivingPermit))
                                        .build(),
                                Cri.DRIVING_LICENCE));

        var sharedClaims =
                generateSharedClaims(
                        TEST_EMAIL,
                        vcs,
                        List.of(SHARED_CLAIM_ATTR_DRIVING_PERMIT),
                        Cri.DRIVING_LICENCE);

        assertEquals(1, sharedClaims.getDrivingPermit().size());
        assertEquals(Set.of(updatedTestDrivingPermit), sharedClaims.getDrivingPermit());
    }

    @Test
    void
            generatesSharedClaimsShouldReturnDrivingPermitFromDrivingLicenceCriIfTargetCriIsNotDrivingLicence() {
        var updatedTestDrivingPermit =
                createDrivingPermitDetails("another-number", "2062-02-02", "ISSUER", "2005-02-02");
        var vcs =
                List.of(
                        generateIdentityVc(
                                getDlCredentialSubjectBuilder()
                                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                                        .build(),
                                Cri.DRIVING_LICENCE),
                        generateIdentityVc(
                                getDlCredentialSubjectBuilder()
                                        .withDrivingPermit(List.of(updatedTestDrivingPermit))
                                        .build(),
                                Cri.DRIVING_LICENCE));

        var sharedClaims =
                generateSharedClaims(
                        TEST_EMAIL, vcs, List.of(SHARED_CLAIM_ATTR_DRIVING_PERMIT), TEST_CRI);

        assertEquals(
                Set.of(TEST_DRIVING_PERMIT, updatedTestDrivingPermit),
                sharedClaims.getDrivingPermit());
    }

    @Test
    void generatesEmptySetsIfNoAttributePresent() {
        var sharedClaims = generateSharedClaims(TEST_EMAIL, List.of(), ALL_ATTRIBUTES, TEST_CRI);

        assertTrue(sharedClaims.getName().isEmpty());
        assertTrue(sharedClaims.getBirthDate().isEmpty());
        assertTrue(sharedClaims.getAddress().isEmpty());
        assertTrue(sharedClaims.getSocialSecurityRecord().isEmpty());
        assertTrue(sharedClaims.getDrivingPermit().isEmpty());
    }

    @Test
    void doesNotIncludeClaimsIfNoneAllowed() {
        var vcs =
                List.of(
                        vcAddressOne(),
                        generateIdentityVc(
                                IdentityCheckSubject.builder()
                                        .withName(List.of(TEST_NAME))
                                        .withBirthDate(List.of(TEST_DOB))
                                        .withSocialSecurityRecord(List.of(TEST_NINO))
                                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                                        .build()));

        var sharedClaims = generateSharedClaims(TEST_EMAIL, vcs, List.of(), TEST_CRI);

        assertNull(sharedClaims.getEmailAddress());
        assertNull(sharedClaims.getName());
        assertNull(sharedClaims.getBirthDate());
        assertNull(sharedClaims.getAddress());
        assertNull(sharedClaims.getSocialSecurityRecord());
        assertNull(sharedClaims.getDrivingPermit());
    }

    @Test
    void doesNotIncludeAddressFromNonAddressVc() {
        var vcs =
                List.of(
                        generateIdentityVc(
                                IdentityCheckSubject.builder()
                                        .withAddress(List.of(ADDRESS_1))
                                        .build()));

        var sharedClaims = generateSharedClaims(TEST_EMAIL, vcs, ALL_ATTRIBUTES, TEST_CRI);

        assertTrue(sharedClaims.getAddress().isEmpty());
    }

    @Test
    void doesNotIncludeFailedVcAttributes() {
        var vcClaim = vcClaimDcmawPassport();
        vcClaim.getEvidence().get(0).setValidityScore(0);
        vcClaim.setCredentialSubject(
                IdentityCheckSubject.builder()
                        .withName(List.of(TEST_NAME))
                        .withBirthDate(List.of(TEST_DOB))
                        .withAddress(List.of(ADDRESS_1))
                        .withSocialSecurityRecord(List.of(TEST_NINO))
                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                        .build());

        var vcs = List.of(generateVerifiableCredential(TEST_SUBJECT, Cri.DCMAW, vcClaim));

        var sharedClaims = generateSharedClaims(TEST_EMAIL, vcs, ALL_ATTRIBUTES, TEST_CRI);

        assertTrue(sharedClaims.getName().isEmpty());
        assertTrue(sharedClaims.getBirthDate().isEmpty());
        assertTrue(sharedClaims.getAddress().isEmpty());
        assertTrue(sharedClaims.getSocialSecurityRecord().isEmpty());
        assertTrue(sharedClaims.getDrivingPermit().isEmpty());
    }

    @Test
    void includesMultipleAttributes() {
        var otherName = createName("Other", "Name");
        var otherDob = createBirthDate("2000-01-01");
        var otherNino = createSocialSecurityRecordDetails("other-nino");
        var otherDrivingPermit =
                createDrivingPermitDetails("OTHER123456", "2062-02-02", "ISSUER", "2005-02-02");

        var vc = vcDcmawPassport();
        var credential = (IdentityCheckCredential) vc.getCredential();
        credential.getCredentialSubject().setName(List.of(TEST_NAME));

        var vcs =
                List.of(
                        vcAddressOne(),
                        vcAddressTwo(),
                        generateIdentityVc(
                                IdentityCheckSubject.builder()
                                        .withName(List.of(TEST_NAME))
                                        .withBirthDate(List.of(TEST_DOB))
                                        .withSocialSecurityRecord(List.of(TEST_NINO))
                                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                                        .build()),
                        generateIdentityVc(
                                IdentityCheckSubject.builder()
                                        .withName(List.of(otherName))
                                        .withBirthDate(List.of(otherDob))
                                        .withSocialSecurityRecord(List.of(otherNino))
                                        .withDrivingPermit(List.of(otherDrivingPermit))
                                        .build()));

        var sharedClaims = generateSharedClaims(TEST_EMAIL, vcs, ALL_ATTRIBUTES, TEST_CRI);

        assertEquals(Set.of(TEST_NAME, otherName), sharedClaims.getName());
        assertEquals(Set.of(TEST_DOB, otherDob), sharedClaims.getBirthDate());
        assertEquals(Set.of(ADDRESS_1, ADDRESS_2), sharedClaims.getAddress());
        assertEquals(Set.of(TEST_NINO, otherNino), sharedClaims.getSocialSecurityRecord());
        assertEquals(
                Set.of(TEST_DRIVING_PERMIT, otherDrivingPermit), sharedClaims.getDrivingPermit());
    }

    @Test
    void deduplicatesAttributes() {
        var vcs =
                List.of(
                        vcAddressOne(),
                        vcAddressOne(),
                        generateIdentityVc(
                                IdentityCheckSubject.builder()
                                        .withName(List.of(TEST_NAME))
                                        .withBirthDate(List.of(TEST_DOB))
                                        .withSocialSecurityRecord(List.of(TEST_NINO))
                                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                                        .build()),
                        generateIdentityVc(
                                IdentityCheckSubject.builder()
                                        .withName(List.of(TEST_NAME))
                                        .withBirthDate(List.of(TEST_DOB))
                                        .withSocialSecurityRecord(List.of(TEST_NINO))
                                        .withDrivingPermit(List.of(TEST_DRIVING_PERMIT))
                                        .build()));

        var sharedClaims = generateSharedClaims(TEST_EMAIL, vcs, ALL_ATTRIBUTES, TEST_CRI);

        assertEquals(Set.of(TEST_NAME), sharedClaims.getName());
        assertEquals(Set.of(TEST_DOB), sharedClaims.getBirthDate());
        assertEquals(Set.of(ADDRESS_1), sharedClaims.getAddress());
        assertEquals(Set.of(TEST_NINO), sharedClaims.getSocialSecurityRecord());
        assertEquals(Set.of(TEST_DRIVING_PERMIT), sharedClaims.getDrivingPermit());
    }

    private VerifiableCredential generateIdentityVc(IdentityCheckSubject subject) {
        return generateIdentityVc(subject, Cri.DCMAW);
    }

    private VerifiableCredential generateIdentityVc(IdentityCheckSubject subject, Cri cri) {
        var vcClaim = vcClaimDcmawPassport();
        vcClaim.setCredentialSubject(subject);

        return generateVerifiableCredential(TEST_SUBJECT, cri, vcClaim);
    }
}
