package uk.gov.di.ipv.core.library.fixtures;

import com.nimbusds.jose.jwk.KeyType;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.helpers.TestVc;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.CheckDetails;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.RiskAssessment;
import uk.gov.di.model.RiskAssessmentCredential;
import uk.gov.di.model.SocialSecurityRecordDetails;
import uk.gov.di.model.VerifiableCredentialType;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.Cri.NINO;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.RISK_ASSESSMENT_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME_PARTS;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.vocab.BankAccountGenerator.createBankAccountDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator.createBirthDate;
import static uk.gov.di.ipv.core.library.helpers.vocab.DrivingPermitDetailsGenerator.createDrivingPermitDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.IdCardDetailsGenerator.createIdCardDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.NamePartGenerator.createNamePart;
import static uk.gov.di.ipv.core.library.helpers.vocab.PassportDetailsGenerator.createPassportDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.PostalAddressGenerator.createPostalAddress;
import static uk.gov.di.ipv.core.library.helpers.vocab.ResidencePermitDetailsGenerator.createResidencePermitDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.SocialSecurityRecordDetailsGenerator.createSocialSecurityRecordDetails;
import static uk.gov.di.model.NamePart.NamePartType.FAMILY_NAME;
import static uk.gov.di.model.NamePart.NamePartType.GIVEN_NAME;

public interface VcFixtures {
    String TEST_SUBJECT = "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345";
    String TEST_ISSUER_INTEGRATION = "https://review-a.integration.account.gov.uk";
    String FRAUD_ISSUER_STAGING = "https://review-f.staging.account.gov.uk";
    String FRAUD_ISSUER_INTEGRATION = "https://review-f.integration.account.gov.uk";
    String TICF_ISSUER = "https://ticf.stubs.account.gov.uk";
    String EXPERIAN_KBV_ISSUER_INTEGRATION = "https://review-k.integration.account.gov.uk";

    private static IdentityCheckCredential vcClaimWebPassportValid() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(kennethDecerqueiraName()))
                                .withBirthDate(
                                        List.of(
                                                BirthDate.builder()
                                                        .withValue("1965-07-08")
                                                        .build()))
                                .withPassport(
                                        List.of(
                                                createPassportDetails(
                                                        "321654987", "GBR", "2030-01-01")))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("1c04edf0-a205-4585-8877-be6bd1776a39")
                                        .withStrengthScore(4)
                                        .withValidityScore(2)
                                        .withCi(Collections.emptyList())
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .withIdentityCheckPolicy(
                                                                        CheckDetails
                                                                                .IdentityCheckPolicyType
                                                                                .PUBLISHED)
                                                                .build()))
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimAddressValid(PostalAddress address) {
        return vcClaimAddressValid(List.of(address));
    }

    private static IdentityCheckCredential vcClaimAddressValid(List<PostalAddress> addresses) {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.ADDRESS_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder().withAddress(addresses).build())
                .build();
    }

    private static IdentityCheckCredential vcClaimExperianFraudScore1() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(kennethDecerqueiraName()))
                                .withBirthDate(
                                        List.of(
                                                BirthDate.builder()
                                                        .withValue("1959-08-23")
                                                        .build()))
                                .withAddress(List.of(ADDRESS_3))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("RB000103490087")
                                        .withIdentityFraudScore(1)
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimExperianFraudScore0() {
        var vcClaim = vcClaimExperianFraudScore1();
        vcClaim.getEvidence().get(0).setIdentityFraudScore(0);
        return vcClaim;
    }

    private static IdentityCheckCredential vcClaimExperianFraudScore2() {
        var vcClaim = vcClaimExperianFraudScore1();
        var evidence = vcClaim.getEvidence().get(0);
        evidence.setIdentityFraudScore(2);
        evidence.setCheckDetails(
                List.of(
                        CheckDetails.builder()
                                .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                .withFraudCheck(CheckDetails.FraudCheckType.MORTALITY_CHECK)
                                .build(),
                        CheckDetails.builder()
                                .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                .withFraudCheck(CheckDetails.FraudCheckType.IDENTITY_THEFT_CHECK)
                                .build(),
                        CheckDetails.builder()
                                .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                .withFraudCheck(
                                        CheckDetails.FraudCheckType.SYNTHETIC_IDENTITY_CHECK)
                                .build(),
                        CheckDetails.builder()
                                .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                .withFraudCheck(
                                        CheckDetails.FraudCheckType.IMPERSONATION_RISK_CHECK)
                                .withTxn("RB000180729626")
                                .build(),
                        CheckDetails.builder()
                                .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                .withActivityFrom("1963-01-01")
                                .withIdentityCheckPolicy(CheckDetails.IdentityCheckPolicyType.NONE)
                                .build()));
        return vcClaim;
    }

    private static IdentityCheckCredential vcClaimWebDrivingLicenceDvla() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withAddress(List.of(ADDRESS_4))
                                .withDrivingPermit(List.of(DRIVING_PERMIT_DVLA))
                                .withName(List.of(aliceParkerName()))
                                .withBirthDate(
                                        List.of(
                                                BirthDate.builder()
                                                        .withValue("1965-07-08")
                                                        .build()))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("bcd2346")
                                        .withActivityHistoryScore(1)
                                        .withCi(Collections.emptyList())
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .withIdentityCheckPolicy(
                                                                        CheckDetails
                                                                                .IdentityCheckPolicyType
                                                                                .PUBLISHED)
                                                                .withActivityFrom("2019-01-01")
                                                                .build()))
                                        .withValidityScore(2)
                                        .withStrengthScore(3)
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimWebDrivingLicenceDva() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getCredentialSubject().setDrivingPermit(List.of(DRIVING_PERMIT_DVA));
        vcClaim.getCredentialSubject().setName(List.of(kennethDecerqueiraName()));
        return vcClaim;
    }

    private static IdentityCheckCredential vcClaimNinoIdentityCheck() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(kennethDecerqueiraName()))
                                .withBirthDate(
                                        List.of(
                                                BirthDate.builder()
                                                        .withValue("1965-07-08")
                                                        .build()))
                                .withSocialSecurityRecord(
                                        List.of(
                                                SocialSecurityRecordDetails.builder()
                                                        .withPersonalNumber("AA000003D")
                                                        .build()))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("e5b22348-c866-4b25-bb50-ca2106af7874")
                                        .withStrengthScore(2)
                                        .withValidityScore(2)
                                        .withCi(Collections.emptyList())
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .build()))
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimNinoRecordCheck() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(kennethDecerqueiraName()))
                                .withBirthDate(
                                        List.of(
                                                BirthDate.builder()
                                                        .withValue("1965-07-08")
                                                        .build()))
                                .withSocialSecurityRecord(
                                        List.of(
                                                SocialSecurityRecordDetails.builder()
                                                        .withPersonalNumber("AA000003D")
                                                        .build()))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("e5b22348-c866-4b25-bb50-ca2106af7874")
                                        .withCi(Collections.emptyList())
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withDataCheck(
                                                                        CheckDetails.DataCheckType
                                                                                .RECORD_CHECK)
                                                                .build()))
                                        .build()))
                .build();
    }

    private static RiskAssessmentCredential vcClaimTicf() {
        return RiskAssessmentCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.RISK_ASSESSMENT_CREDENTIAL))
                .withEvidence(
                        List.of(
                                RiskAssessment.builder()
                                        .withType(RISK_ASSESSMENT_EVIDENCE_TYPE)
                                        .withTxn("963deeb5-a52c-4030-a69a-3184f77a4f18")
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimExperianKbv() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(aliceParkerName()))
                                .withAddress(List.of(ADDRESS_4))
                                .withBirthDate(
                                        List.of(
                                                BirthDate.builder()
                                                        .withValue("1970-01-01")
                                                        .build()))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("abc1234")
                                        .withVerificationScore(2)
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .KBV)
                                                                .withKbvQuality(2)
                                                                .withKbvResponseMode(
                                                                        CheckDetails
                                                                                .KBVResponseModeType
                                                                                .FREE_TEXT)
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .KBV)
                                                                .withKbvQuality(2)
                                                                .withKbvResponseMode(
                                                                        CheckDetails
                                                                                .KBVResponseModeType
                                                                                .MULTIPLE_CHOICE)
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .KBV)
                                                                .withKbvQuality(1)
                                                                .withKbvResponseMode(
                                                                        CheckDetails
                                                                                .KBVResponseModeType
                                                                                .MULTIPLE_CHOICE)
                                                                .build()))
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimDcmawDrivingPermitDva() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(morganSarahMeredythName()))
                                .withBirthDate(
                                        List.of(
                                                BirthDate.builder()
                                                        .withValue("1965-07-08")
                                                        .build()))
                                .withAddress(List.of(ADDRESS_4))
                                .withDrivingPermit(List.of(DRIVING_PERMIT_DVA))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("bcd2346")
                                        .withStrengthScore(3)
                                        .withValidityScore(2)
                                        .withActivityHistoryScore(1)
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .VRI)
                                                                .withIdentityCheckPolicy(
                                                                        CheckDetails
                                                                                .IdentityCheckPolicyType
                                                                                .PUBLISHED)
                                                                .withActivityFrom("2019-01-01")
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .BVR)
                                                                .withBiometricVerificationProcessLevel(
                                                                        3)
                                                                .build()))
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimDcmawPassport() {
        var vcClaim = vcClaimDcmawDrivingPermitDva();
        vcClaim.getCredentialSubject().setDrivingPermit(null);
        vcClaim.getCredentialSubject().setPassport(passportDetails());
        vcClaim.getEvidence().get(0).setStrengthScore(4);

        return vcClaim;
    }

    List<TestVc.TestEvidence> SUCCESSFUL_WEB_PASSPORT_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .strengthScore(4)
                            .validityScore(2)
                            .verificationScore(2)
                            .build());

    List<TestVc.TestEvidence> DCMAW_EVIDENCE_VRI_CHECK =
            List.of(
                    TestVc.TestEvidence.builder()
                            .txn("bcd2346")
                            .strengthScore(3)
                            .validityScore(2)
                            .verificationScore(2)
                            .activityHistoryScore(1)
                            .checkDetails(
                                    List.of(
                                            Map.of(
                                                    "checkMethod", "vri",
                                                    "identityCheckPolicy", "published",
                                                    "activityFrom", "2019-01-01"),
                                            Map.of(
                                                    "checkMethod",
                                                    "bvr",
                                                    "biometricVerificationProcessLevel",
                                                    3)))
                            .build());

    List<TestVc.TestEvidence> DCMAW_FAILED_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .txn("bcd2346")
                            .strengthScore(3)
                            .validityScore(0)
                            .activityHistoryScore(1)
                            .failedCheckDetails(
                                    List.of(
                                            Map.of(
                                                    "checkMethod", "vri",
                                                    "identityCheckPolicy", "published",
                                                    "activityFrom", "2019-01-01"),
                                            Map.of(
                                                    "checkMethod",
                                                    "bvr",
                                                    "biometricVerificationProcessLevel",
                                                    2)))
                            .build());

    List<TestVc.TestEvidence> TICF_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .type(RISK_ASSESSMENT_EVIDENCE_TYPE)
                            .txn("963deeb5-a52c-4030-a69a-3184f77a4f18")
                            .checkDetails(null)
                            .build());

    Long TEST_UPRN = Long.valueOf("100120012077");

    PostalAddress ADDRESS_1 =
            createPostalAddress(
                    "35",
                    "",
                    "IDSWORTH ROAD",
                    "S5 6UN",
                    "SHEFFIELD",
                    "GB",
                    TEST_UPRN,
                    "2000-01-01",
                    null);

    PostalAddress ADDRESS_2 =
            createPostalAddress(
                    "8",
                    "221B",
                    "MILTON ROAD",
                    "MK15 5BX",
                    "Milton Keynes",
                    "GB",
                    TEST_UPRN,
                    "2024-01-01",
                    null);

    PostalAddress ADDRESS_3 =
            createPostalAddress(
                    "8", "", "HADLEY ROAD", "BA2 5AA", "BATH", "GB", TEST_UPRN, null, "2000-01-01");

    PostalAddress ADDRESS_4 =
            createPostalAddress(
                    "16",
                    "COY POND BUSINESS PARK",
                    "BIG STREET",
                    "HP16 0AL",
                    "GREAT MISSENDEN",
                    "GB",
                    TEST_UPRN,
                    null,
                    null,
                    "UNIT 2B",
                    "FINCH GROUP",
                    "KINGS PARK",
                    "SOME DISTRICT",
                    "LONG EATON");

    List<PostalAddress> MULTIPLE_ADDRESSES_VALID =
            List.of(
                    ADDRESS_3,
                    createPostalAddress(
                            "3",
                            "",
                            "STOCKS HILL",
                            "CA14 5PH",
                            "HARRINGTON",
                            "GB",
                            TEST_UPRN,
                            "2011-01-01",
                            null),
                    createPostalAddress(
                            "24",
                            "",
                            "SOME STREET",
                            "TE5 7ER",
                            "SOME LOCALITY",
                            "GB",
                            TEST_UPRN,
                            null,
                            "2011-01-01"));

    List<PostalAddress> MULTIPLE_ADDRESSES_NO_VALID_FROM =
            List.of(
                    ADDRESS_3,
                    createPostalAddress(
                            "3",
                            "",
                            "STOCKS HILL",
                            "CA14 5PH",
                            "HARRINGTON",
                            "GB",
                            TEST_UPRN,
                            null,
                            null),
                    createPostalAddress(
                            "24",
                            "",
                            "SOME STREET",
                            "TE5 7ER",
                            "SOME LOCALITY",
                            "GB",
                            TEST_UPRN,
                            null,
                            null));

    private static Name aliceParkerName() {
        return Name.builder()
                .withNameParts(
                        List.of(
                                NamePart.builder().withType(GIVEN_NAME).withValue("Alice").build(),
                                NamePart.builder().withType(GIVEN_NAME).withValue("Jane").build(),
                                NamePart.builder()
                                        .withType(FAMILY_NAME)
                                        .withValue("Parker")
                                        .build()))
                .build();
    }

    private static Name kennethDecerqueiraName() {
        return Name.builder()
                .withNameParts(
                        List.of(
                                NamePart.builder()
                                        .withType(GIVEN_NAME)
                                        .withValue("KENNETH")
                                        .build(),
                                NamePart.builder()
                                        .withType(FAMILY_NAME)
                                        .withValue("DECERQUEIRA")
                                        .build()))
                .build();
    }

    private static Name morganSarahMeredythName() {
        return Name.builder()
                .withNameParts(
                        List.of(
                                NamePart.builder().withType(GIVEN_NAME).withValue("MORGAN").build(),
                                NamePart.builder()
                                        .withType(FAMILY_NAME)
                                        .withValue("SARAH MEREDYTH")
                                        .build()))
                .build();
    }

    Map<String, List<NamePart>> ALICE_PARKER_NAME =
            Map.of(
                    VC_NAME_PARTS,
                    List.of(
                            createNamePart("Alice", GIVEN_NAME),
                            createNamePart("Jane", GIVEN_NAME),
                            createNamePart("Parker", FAMILY_NAME)));
    Map<String, List<NamePart>> MORGAN_SARAH_MEREDYTH_NAME =
            Map.of(
                    VC_NAME_PARTS,
                    List.of(
                            createNamePart("MORGAN", GIVEN_NAME),
                            createNamePart("SARAH MEREDYTH", FAMILY_NAME)));

    Map<String, List<NamePart>> MARY_WATSON_NAME =
            Map.of(
                    VC_NAME_PARTS,
                    List.of(
                            createNamePart("Mary", GIVEN_NAME),
                            createNamePart("Watson", FAMILY_NAME)));

    DrivingPermitDetails DRIVING_PERMIT_DVA =
            createDrivingPermitDetails("MORGA753116SM9IJ", "2042-10-01", "DVA", "2018-04-19");

    DrivingPermitDetails DRIVING_PERMIT_DVLA =
            createDrivingPermitDetails(
                    "PARKE710112PBFGA", "2032-02-02", "DVLA", "2005-02-02", "123456");

    static List<PassportDetails> passportDetails() {
        return List.of(createPassportDetails("321654987", "GBR", "2030-01-01"));
    }

    static VerifiableCredential vcWebPassportSuccessful() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaimWebPassportValid(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportSuccessfulWithRsaKeyType() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaimWebPassportValid(),
                Instant.ofEpochSecond(1705986521),
                KeyType.RSA);
    }

    static VerifiableCredential vcWebPassportM1aFailed() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        var evidence = vcClaim.getEvidence().get(0);
        evidence.setValidityScore(0);
        evidence.setVerificationScore(0);

        return generateVerifiableCredential(
                TEST_SUBJECT, Cri.PASSPORT, vcClaim, Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportM1aWithCI() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getEvidence().get(0).setCi(List.of("test"));

        return generateVerifiableCredential(
                TEST_SUBJECT, Cri.PASSPORT, vcClaim, Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportM1aMissingEvidence() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.setEvidence(Collections.emptyList());

        return generateVerifiableCredential(
                TEST_SUBJECT, Cri.PASSPORT, vcClaim, Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportMissingName() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getCredentialSubject().setName(Collections.emptyList());

        return generateVerifiableCredential(
                TEST_SUBJECT, Cri.PASSPORT, vcClaim, Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportMissingBirthDate() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getCredentialSubject().setBirthDate(Collections.emptyList());

        return generateVerifiableCredential(TEST_SUBJECT, Cri.PASSPORT, vcClaim);
    }

    static VerifiableCredential vcWebPassportInvalidBirthDate() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getCredentialSubject()
                .setBirthDate(List.of(BirthDate.builder().withValue("invalid").build()));

        return generateVerifiableCredential(TEST_SUBJECT, Cri.PASSPORT, vcClaim);
    }

    static VerifiableCredential vcWebPassportEmptyPassportDetails() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getCredentialSubject().setPassport(Collections.emptyList());

        return generateVerifiableCredential(TEST_SUBJECT, Cri.PASSPORT, vcClaim);
    }

    static VerifiableCredential vcWebPassportMissingPassportDetails() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getCredentialSubject().setPassport(null);

        return generateVerifiableCredential(TEST_SUBJECT, Cri.PASSPORT, vcClaim);
    }

    static VerifiableCredential vcWebPassportClaimInvalidType() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.setType(
                List.of(
                        VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                        VerifiableCredentialType.ADDRESS_CREDENTIAL));

        return generateVerifiableCredential(TEST_SUBJECT, Cri.PASSPORT, vcClaim);
    }

    private static VerifiableCredential generateAddressVc(IdentityCheckCredential vcClaim) {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.ADDRESS,
                vcClaim,
                TEST_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1658829720));
    }

    static VerifiableCredential vcAddressOne() {
        return generateAddressVc(vcClaimAddressValid(ADDRESS_1));
    }

    static VerifiableCredential vcAddressEmpty() {
        var vcClaim = vcClaimAddressValid((List<PostalAddress>) null);
        return generateAddressVc(vcClaim);
    }

    static VerifiableCredential vcAddressNoCredentialSubject() {
        var vcClaim = vcClaimAddressValid(ADDRESS_1);
        vcClaim.setCredentialSubject(null);
        return generateAddressVc(vcClaim);
    }

    static VerifiableCredential vcAddressTwo() {
        return generateAddressVc(vcClaimAddressValid(ADDRESS_2));
    }

    static VerifiableCredential vcAddressM1a() {
        return generateAddressVc(vcClaimAddressValid(ADDRESS_3));
    }

    static VerifiableCredential vcAddressMultipleAddresses() {
        return generateAddressVc(vcClaimAddressValid(MULTIPLE_ADDRESSES_VALID));
    }

    static VerifiableCredential vcAddressMultipleAddressesNoValidFrom() {
        return generateAddressVc(vcClaimAddressValid(MULTIPLE_ADDRESSES_NO_VALID_FROM));
    }

    static VerifiableCredential vcExperianFraudM1a() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                Instant.now().minusSeconds(10));
    }

    static VerifiableCredential vcExperianFraudM1aExpired() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcExperianFraudEvidenceFailed() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore0(),
                FRAUD_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcExperianFraudScoreTwo() {
        return generateVerifiableCredential(
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore2(),
                FRAUD_ISSUER_STAGING,
                Instant.ofEpochSecond(1704290386));
    }

    static VerifiableCredential vcExperianFraudExpired() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcExperianFraudNotExpired() {
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime sixMonthsLater = now.plusMonths(6);
        Instant futureInstant = sixMonthsLater.toInstant();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                futureInstant);
    }

    static VerifiableCredential vcExperianFraudScoreOne() {
        return generateVerifiableCredential(
                "user-id",
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_STAGING,
                Instant.ofEpochSecond(1652953380));
    }

    static VerifiableCredential vcExperianFraudMissingName() {
        var vcClaim = vcClaimExperianFraudScore1();
        vcClaim.getCredentialSubject().setName(Collections.emptyList());

        return generateVerifiableCredential(
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                EXPERIAN_FRAUD,
                vcClaim,
                FRAUD_ISSUER_STAGING,
                Instant.ofEpochSecond(1704290386));
    }

    static VerifiableCredential vcExperianFraudApplicableAuthoritativeSourceFailed() {
        var vcClaim = vcClaimExperianFraudScore0();
        vcClaim.getEvidence()
                .get(0)
                .setFailedCheckDetails(
                        List.of(
                                CheckDetails.builder()
                                        .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                        .withFraudCheck(
                                                CheckDetails.FraudCheckType
                                                        .APPLICABLE_AUTHORITATIVE_SOURCE)
                                        .build()));

        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaim,
                FRAUD_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcExperianFraudAvailableAuthoritativeFailed() {
        var vcClaim = vcClaimExperianFraudScore0();
        vcClaim.getEvidence()
                .get(0)
                .setFailedCheckDetails(
                        List.of(
                                CheckDetails.builder()
                                        .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                        .withFraudCheck(
                                                CheckDetails.FraudCheckType
                                                        .AVAILABLE_AUTHORITATIVE_SOURCE)
                                        .build()));

        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaim,
                FRAUD_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcWebDrivingPermitDvaValid() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaimWebDrivingLicenceDva(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitMissingDrivingPermit() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getCredentialSubject().setDrivingPermit(null);

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitEmptyDrivingPermit() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getCredentialSubject().setDrivingPermit(Collections.emptyList());

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitFailedChecks() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getEvidence().get(0).setValidityScore(0);

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                Instant.ofEpochSecond(1705468290));
    }

    static VerifiableCredential vcWebDrivingPermitDvlaValid() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaimWebDrivingLicenceDvla(),
                "https://driving-license-cri.stubs.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static VerifiableCredential vcWebDrivingPermitNoCredentialSubjectProperty() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.setCredentialSubject(null);

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitIncorrectType() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.setType(
                List.of(
                        VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                        VerifiableCredentialType.ADDRESS_CREDENTIAL));

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                Instant.ofEpochSecond(1705986521));
    }

    private static VerifiableCredential generateNinoVc(IdentityCheckCredential vcClaim) {
        return generateVerifiableCredential(
                "urn:uuid:51dfa9ac-8624-4b93-aa8f-99ed772ff0ec",
                NINO,
                vcClaim,
                "https://review-xx.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static VerifiableCredential vcNinoIdentityCheckSuccessful() {
        return generateNinoVc(vcClaimNinoIdentityCheck());
    }

    static VerifiableCredential vcNinoIdentityCheckUnsuccessful() {
        var vcClaim = vcClaimNinoIdentityCheck();
        var evidence = vcClaim.getEvidence().get(0);
        evidence.setCheckDetails(null);
        evidence.setFailedCheckDetails(
                List.of(
                        CheckDetails.builder()
                                .withCheckMethod(CheckDetails.CheckMethodType.DATA)
                                .build()));
        evidence.setValidityScore(0);

        return generateNinoVc(vcClaim);
    }

    static VerifiableCredential vcNinoIdentityCheckMissingSocialSecurityRecord() {
        var vcClaim = vcClaimNinoIdentityCheck();
        vcClaim.getCredentialSubject().setSocialSecurityRecord(null);

        return generateNinoVc(vcClaim);
    }

    static VerifiableCredential vcNinoIdentityCheckEmptySocialSecurityRecord() {
        var vcClaim = vcClaimNinoIdentityCheck();
        vcClaim.getCredentialSubject().setSocialSecurityRecord(Collections.emptyList());

        return generateNinoVc(vcClaim);
    }

    static VerifiableCredential vcNinoInvalidVcType() {
        var vcClaim = vcClaimNinoIdentityCheck();
        vcClaim.setType(
                List.of(
                        VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                        VerifiableCredentialType.RISK_ASSESSMENT_CREDENTIAL));

        return generateNinoVc(vcClaim);
    }

    static VerifiableCredential vcTicf() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                TICF,
                vcClaimTicf(),
                TICF_ISSUER,
                Instant.ofEpochSecond(1704822570));
    }

    static VerifiableCredential vcTicfWithCi() {
        var vcClaim = vcClaimTicf();
        vcClaim.getEvidence().get(0).setCi(List.of("test"));

        return generateVerifiableCredential(
                TEST_SUBJECT, TICF, vcClaim, TICF_ISSUER, Instant.ofEpochSecond(1704822570));
    }

    static VerifiableCredential vcExperianKbvM1a() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                Cri.EXPERIAN_KBV,
                vcClaimExperianKbv(),
                EXPERIAN_KBV_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1653403140));
    }

    static VerifiableCredential vcDcmawDrivingPermitDvaM1b() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimDcmawDrivingPermitDva(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawPassport() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimDcmawPassport(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawAsyncDrivingPermitDva() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DCMAW_ASYNC,
                vcClaimDcmawDrivingPermitDva(),
                "https://dcmaw-async.stubs.account.gov.uk/async/credential",
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawAsyncPassport() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DCMAW_ASYNC,
                vcClaimDcmawPassport(),
                "https://dcmaw-async.stubs.account.gov.uk/async/credential",
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcF2fPassportM1a() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(List.of(MARY_WATSON_NAME))
                        .passport(List.of(createPassportDetails("824159121", null, "2030-01-01")))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("24929d38-420c-4ba9-b846-3005ee691e26")
                                                .strengthScore(4)
                                                .validityScore(2)
                                                .verificationScore(2)
                                                .checkDetails(
                                                        List.of(
                                                                Map.of(
                                                                        "checkMethod",
                                                                        "vri",
                                                                        "identityCheckPolicy",
                                                                        "published",
                                                                        "txn",
                                                                        "24929d38-420c-4ba9-b846-3005ee691e26"),
                                                                Map.of(
                                                                        "checkMethod",
                                                                        "pvr",
                                                                        "biometricVerificationProcessLevel",
                                                                        3,
                                                                        "txn",
                                                                        "24929d38-420c-4ba9-b846-3005ee691e26")))
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcF2fDrivingLicenceM1a() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("bcd2346")
                                                .strengthScore(3)
                                                .validityScore(2)
                                                .activityHistoryScore(1)
                                                .checkDetails(
                                                        List.of(
                                                                Map.of(
                                                                        "checkMethod",
                                                                        "vri",
                                                                        "identityCheckPolicy",
                                                                        "published",
                                                                        "activityFrom",
                                                                        "2019-01-01"),
                                                                Map.of(
                                                                        "checkMethod",
                                                                        "bvr",
                                                                        "biometricVerificationProcessLevel",
                                                                        2)))
                                                .build()))
                        .credentialSubject(
                                TestVc.TestCredentialSubject.builder()
                                        .name(List.of(MORGAN_SARAH_MEREDYTH_NAME))
                                        .address(List.of(ADDRESS_4))
                                        .drivingPermit(List.of(DRIVING_PERMIT_DVA))
                                        .build())
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcF2fBrp() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(
                                List.of(
                                        Map.of(
                                                VC_NAME_PARTS,
                                                List.of(
                                                        createNamePart(
                                                                "Chris",
                                                                NamePart.NamePartType
                                                                        .GIVEN_NAME)))))
                        .birthDate(List.of(createBirthDate("1984-09-28")))
                        .residencePermit(
                                List.of(
                                        createResidencePermitDetails(
                                                "AX66K69P2", "2030-07-13", "CR", "UTO")))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("some-uuid")
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1652953080));
    }

    static VerifiableCredential vcF2fIdCard() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(
                                List.of(
                                        Map.of(
                                                VC_NAME_PARTS,
                                                List.of(
                                                        createNamePart(
                                                                "Chris",
                                                                NamePart.NamePartType
                                                                        .GIVEN_NAME)))))
                        .birthDate(List.of(createBirthDate("1984-09-28")))
                        .idCard(
                                List.of(
                                        createIdCardDetails(
                                                "SPEC12031", "2031-08-02", "NLD", "2021-08-02")))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("some-uuid")
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1652953080));
    }

    static VerifiableCredential vcF2fSocialSecurityCard() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .socialSecurityRecord(
                                List.of(
                                        createSocialSecurityRecordDetails(
                                                "AB123456C"))) // pragma: allowlist secret
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("some-uuid")
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1652953080));
    }

    static VerifiableCredential vcF2fBankAccount() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .bankAccount(
                                List.of(
                                        createBankAccountDetails(
                                                "123456323",
                                                "20-55-77",
                                                "20042020",
                                                "20042025"))) // pragma: allowlist secret
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("some-uuid")
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1652953080));
    }

    static VerifiableCredential l1AEvidenceVc() {
        var evidence = TestVc.TestEvidence.builder().strengthScore(2).validityScore(2).build();

        return generateVerifiableCredential(
                TEST_SUBJECT, NINO, TestVc.builder().evidence(List.of(evidence)).build());
    }

    static VerifiableCredential vcHmrcMigrationPCL200() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .socialSecurityRecord(
                                List.of(
                                        createSocialSecurityRecordDetails(
                                                "AB123456C"))) // pragma: allowlist secret
                        .build();
        TestVc.TestEvidence evidence =
                TestVc.TestEvidence.builder()
                        .txn("d22f8cb1")
                        .strengthScore(3)
                        .validityScore(2)
                        .verificationScore(3)
                        .checkDetails(List.of(Map.of("checkMethod", "data")))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                HMRC_MIGRATION,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(List.of(evidence))
                        .build(),
                "https://orch.stubs.account.gov.uk/migration/v1",
                Vot.PCL200.toString(),
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcHmrcMigrationPCL250() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .passport(passportDetails())
                        .socialSecurityRecord(
                                List.of(
                                        createSocialSecurityRecordDetails(
                                                "AB123456C"))) // pragma: allowlist secret
                        .build();
        TestVc.TestEvidence evidence =
                TestVc.TestEvidence.builder()
                        .txn("d22f8cb1")
                        .strengthScore(3)
                        .validityScore(2)
                        .verificationScore(3)
                        .checkDetails(List.of(Map.of("checkMethod", "data")))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                HMRC_MIGRATION,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(List.of(evidence))
                        .build(),
                "https://orch.stubs.account.gov.uk/migration/v1",
                Vot.PCL250.toString(),
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcHmrcMigrationPCL200NoEvidence() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .passport(passportDetails())
                        .socialSecurityRecord(
                                List.of(
                                        createSocialSecurityRecordDetails(
                                                "AB123456C"))) // pragma: allowlist secret
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                HMRC_MIGRATION,
                TestVc.builder()
                        .evidence(Collections.emptyList())
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://orch.stubs.account.gov.uk/migration/v1",
                Vot.PCL200.toString(),
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcHmrcMigrationPCL250NoEvidence() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .socialSecurityRecord(
                                List.of(
                                        createSocialSecurityRecordDetails(
                                                "AB123456C"))) // pragma: allowlist secret
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                HMRC_MIGRATION,
                TestVc.builder().evidence(null).credentialSubject(credentialSubject).build(),
                "https://orch.stubs.account.gov.uk/migration/v1",
                Vot.PCL250.toString(),
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcInvalidVot() throws Exception {
        return generateVerifiableCredential(
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                null,
                TestVc.builder().evidence(SUCCESSFUL_WEB_PASSPORT_EVIDENCE).build(),
                "https://review-p.staging.account.gov.uk",
                "not-a-vot",
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcNullVot() throws Exception {
        return generateVerifiableCredential(
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                null,
                TestVc.builder().evidence(SUCCESSFUL_WEB_PASSPORT_EVIDENCE).build(),
                "https://review-p.staging.account.gov.uk",
                null,
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }
}
