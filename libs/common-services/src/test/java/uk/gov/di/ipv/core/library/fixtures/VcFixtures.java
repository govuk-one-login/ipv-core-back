package uk.gov.di.ipv.core.library.fixtures;

import com.nimbusds.jose.jwk.KeyType;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.helpers.TestVc;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PostalAddress;

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
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.ADDRESS_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.RISK_ASSESSMENT_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.RISK_ASSESSMENT_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME_PARTS;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;
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
    String TEST_ISSUER_STAGING = "https://review-f.staging.account.gov.uk";

    List<TestVc.TestEvidence> SUCCESSFUL_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .strengthScore(4)
                            .validityScore(2)
                            .verificationScore(2)
                            .build());
    List<TestVc.TestEvidence> UNSUCCESSFUL_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .strengthScore(4)
                            .validityScore(0)
                            .verificationScore(0)
                            .build());
    List<TestVc.TestEvidence> TEST_CI_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .strengthScore(4)
                            .validityScore(2)
                            .verificationScore(2)
                            .ci(List.of("test"))
                            .build());

    List<TestVc.TestEvidence> FRAUD_EVIDENCE_NO_CHECK_DETAILS =
            List.of(
                    TestVc.TestEvidence.builder()
                            .checkDetails(null)
                            .txn("RB000103490087")
                            .identityFraudScore(1)
                            .build());

    List<TestVc.TestEvidence> FRAUD_FAILED_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .checkDetails(null)
                            .txn("RB000103490087")
                            .identityFraudScore(0)
                            .build());

    List<TestVc.TestEvidence> FRAUD_EVIDENCE_WITH_CHECK_DETAILS =
            List.of(
                    TestVc.TestEvidence.builder()
                            .txn("RB000180729610")
                            .identityFraudScore(2)
                            .checkDetails(
                                    List.of(
                                            Map.of(
                                                    "checkMethod", "data",
                                                    "fraudCheck", "mortality_check"),
                                            Map.of(
                                                    "checkMethod", "data",
                                                    "fraudCheck", "identity_theft_check"),
                                            Map.of(
                                                    "checkMethod", "data",
                                                    "fraudCheck", "synthetic_identity_check"),
                                            Map.of(
                                                    "txn", "RB000180729626",
                                                    "checkMethod", "data",
                                                    "fraudCheck", "impersonation_risk_check"),
                                            Map.of(
                                                    "checkMethod", "data",
                                                    "activityFrom", "1963-01-01",
                                                    "identityCheckPolicy", "none")))
                            .build());

    List<TestVc.TestEvidence> FRAUD_EVIDENCE_CRI_STUB_CHECK =
            List.of(
                    TestVc.TestEvidence.builder()
                            .checkDetails(null)
                            .type(IDENTITY_CHECK_EVIDENCE_TYPE)
                            .txn("some-uuid")
                            .identityFraudScore(1)
                            .build());

    List<TestVc.TestEvidence> FRAUD_EVIDENCE_FAILED_APPLICABLE_AUTHORITATIVE_SOURCE_CHECK_DETAILS =
            List.of(
                    TestVc.TestEvidence.builder()
                            .checkDetails(null)
                            .failedCheckDetails(
                                    List.of(
                                            Map.of(
                                                    "checkMethod", "data",
                                                    "fraudCheck",
                                                            "applicable_authoritative_source")))
                            .type(IDENTITY_CHECK_EVIDENCE_TYPE)
                            .txn("some-uuid")
                            .build());

    List<TestVc.TestEvidence> FRAUD_EVIDENCE_FAILED_AUTHORITATIVE_AVAILABLE_SOURCE_CHECK_DETAILS =
            List.of(
                    TestVc.TestEvidence.builder()
                            .checkDetails(null)
                            .failedCheckDetails(
                                    List.of(
                                            Map.of(
                                                    "checkMethod",
                                                    "data",
                                                    "fraudCheck",
                                                    "available_authoritative_source")))
                            .type(IDENTITY_CHECK_EVIDENCE_TYPE)
                            .txn("some-uuid")
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

    List<TestVc.TestEvidence> DCMAW_EVIDENCE_DATA_CHECK =
            List.of(
                    TestVc.TestEvidence.builder()
                            .txn("cbf56c46-f33a-49de-8be0-c6318d8eecfc")
                            .strengthScore(3)
                            .validityScore(2)
                            .activityHistoryScore(1)
                            .checkDetails(
                                    List.of(
                                            Map.of(
                                                    "checkMethod", "data",
                                                    "identityCheckPolicy", "published",
                                                    "activityFrom", "1982-05-23")))
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
            createDrivingPermitDetails(
                    "MORGA753116SM9IJ", "2042-10-01", "DVA", "2018-04-19", "123456");

    DrivingPermitDetails DRIVING_PERMIT_DVLA =
            createDrivingPermitDetails("PARKE710112PBFGA", "2032-02-02", "DVLA", "2005-02-02");

    DrivingPermitDetails INVALID_DRIVING_PERMIT =
            createDrivingPermitDetails("MORGA753116SM9IJ", "2042-10-01", null, null);

    List<PassportDetails> PASSPORT_DETAILS =
            List.of(createPassportDetails("321654987", "GBR", "2030-01-01"));

    VerifiableCredential PASSPORT_NON_DCMAW_SUCCESSFUL_VC =
            generateVerifiableCredential(
                    TEST_SUBJECT,
                    Cri.PASSPORT,
                    TestVc.builder()
                            .credentialSubject(
                                    TestVc.TestCredentialSubject.builder()
                                            .passport(PASSPORT_DETAILS)
                                            .build())
                            .evidence(SUCCESSFUL_EVIDENCE)
                            .build(),
                    Instant.ofEpochSecond(1705986521));

    VerifiableCredential PASSPORT_NON_DCMAW_SUCCESSFUL_RSA_SIGNED_VC =
            generateVerifiableCredential(
                    TEST_SUBJECT,
                    Cri.PASSPORT,
                    TestVc.builder()
                            .credentialSubject(
                                    TestVc.TestCredentialSubject.builder()
                                            .passport(PASSPORT_DETAILS)
                                            .build())
                            .evidence(SUCCESSFUL_EVIDENCE)
                            .build(),
                    Instant.ofEpochSecond(1705986521),
                    KeyType.RSA);

    static VerifiableCredential vcPassportM1aFailed() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().passport(PASSPORT_DETAILS).build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(UNSUCCESSFUL_EVIDENCE)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcPassportM1aWithCI() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().passport(PASSPORT_DETAILS).build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(TEST_CI_EVIDENCE)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcPassportM1aMissingEvidence() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().passport(PASSPORT_DETAILS).build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(Collections.emptyList())
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcPassportMissingName() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .passport(PASSPORT_DETAILS)
                        .name(Collections.emptyList())
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static VerifiableCredential vcPassportMissingBirthDate() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .passport(PASSPORT_DETAILS)
                        .birthDate(Collections.emptyList())
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static VerifiableCredential vcPassportInvalidBirthDate() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .passport(PASSPORT_DETAILS)
                        .birthDate(List.of(createBirthDate("invalid")))
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static VerifiableCredential vcPassportMissingPassport() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().passport(Collections.emptyList()).build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static VerifiableCredential vcMissingPassportProperty() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static VerifiableCredential vcPassportClaimInvalidType() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                TestVc.builder()
                        .type(new String[] {VERIFIABLE_CREDENTIAL_TYPE, ADDRESS_CREDENTIAL_TYPE})
                        .build());
    }

    static VerifiableCredential generateAddressVc(TestVc.TestCredentialSubject subject) {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.ADDRESS,
                TestVc.builder()
                        .type(new String[] {VERIFIABLE_CREDENTIAL_TYPE, ADDRESS_CREDENTIAL_TYPE})
                        .credentialSubject(subject)
                        .evidence(null)
                        .build(),
                TEST_ISSUER_INTEGRATION,
                Instant.ofEpochSecond(1658829720));
    }

    VerifiableCredential VC_ADDRESS =
            generateAddressVc(
                    TestVc.TestCredentialSubject.builder()
                            .address(List.of(ADDRESS_1))
                            .name(null)
                            .birthDate(null)
                            .build());

    static VerifiableCredential vcAddressEmpty() {
        return generateAddressVc(TestVc.TestCredentialSubject.builder().build());
    }

    static VerifiableCredential vcAddressNoCredentialSubject() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.ADDRESS,
                TestVc.builder()
                        .type(new String[] {VERIFIABLE_CREDENTIAL_TYPE, ADDRESS_CREDENTIAL_TYPE})
                        .credentialSubject(null)
                        .evidence(null)
                        .build());
    }

    static VerifiableCredential vcAddressTwo() {
        return generateAddressVc(
                TestVc.TestCredentialSubject.builder()
                        .name(List.of(ALICE_PARKER_NAME))
                        .address(List.of(ADDRESS_2))
                        .build());
    }

    VerifiableCredential M1A_ADDRESS_VC =
            generateAddressVc(
                    TestVc.TestCredentialSubject.builder()
                            .name(null)
                            .birthDate(null)
                            .address(List.of(ADDRESS_3))
                            .build());

    static VerifiableCredential vcAddressMultipleAddresses() {
        return generateAddressVc(
                TestVc.TestCredentialSubject.builder()
                        .name(null)
                        .address(MULTIPLE_ADDRESSES_VALID)
                        .build());
    }

    static VerifiableCredential vcAddressMultipleAddressesNoValidFrom() {
        return generateAddressVc(
                TestVc.TestCredentialSubject.builder()
                        .name(null)
                        .address(MULTIPLE_ADDRESSES_NO_VALID_FROM)
                        .build());
    }

    VerifiableCredential M1A_EXPERIAN_FRAUD_VC =
            generateVerifiableCredential(
                    TEST_SUBJECT,
                    Cri.EXPERIAN_FRAUD,
                    TestVc.builder()
                            .evidence(FRAUD_EVIDENCE_NO_CHECK_DETAILS)
                            .credentialSubject(
                                    TestVc.TestCredentialSubject.builder()
                                            .address(List.of(ADDRESS_3))
                                            .birthDate(List.of(createBirthDate("1959-08-23")))
                                            .build())
                            .build(),
                    "https://review-f.integration.account.gov.uk",
                    Instant.now().minusSeconds(10));

    VerifiableCredential EXPIRED_M1A_EXPERIAN_FRAUD_VC =
            generateVerifiableCredential(
                    TEST_SUBJECT,
                    Cri.EXPERIAN_FRAUD,
                    TestVc.builder()
                            .evidence(FRAUD_EVIDENCE_NO_CHECK_DETAILS)
                            .credentialSubject(
                                    TestVc.TestCredentialSubject.builder()
                                            .address(List.of(ADDRESS_3))
                                            .birthDate(List.of(createBirthDate("1959-08-23")))
                                            .build())
                            .build(),
                    "https://review-f.integration.account.gov.uk",
                    Instant.ofEpochSecond(1658829758));

    static VerifiableCredential vcExperianFraudEvidenceFailed() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .birthDate(List.of(createBirthDate("1959-08-23")))
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(FRAUD_FAILED_EVIDENCE)
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://review-f.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcExperianFraudScoreTwo() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().address(List.of(ADDRESS_3)).build();
        return generateVerifiableCredential(
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_WITH_CHECK_DETAILS)
                        .credentialSubject(credentialSubject)
                        .build(),
                TEST_ISSUER_STAGING,
                Instant.ofEpochSecond(1704290386));
    }

    static VerifiableCredential vcFraudExpired() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .birthDate(List.of(createBirthDate("1959-08-23")))
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_NO_CHECK_DETAILS)
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://review-f.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcFraudNotExpired() {
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime sixMonthsLater = now.plusMonths(6);
        Instant futureInstant = sixMonthsLater.toInstant();
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .birthDate(List.of(createBirthDate("1959-08-23")))
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_NO_CHECK_DETAILS)
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://review-f.integration.account.gov.uk",
                futureInstant);
    }

    static VerifiableCredential vcExperianFraudScoreOne() {
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
                        .address(List.of(ADDRESS_1))
                        .birthDate(List.of(createBirthDate("1984-09-28")))
                        .build();
        return generateVerifiableCredential(
                "user-id",
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_CRI_STUB_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                TEST_ISSUER_STAGING,
                Instant.ofEpochSecond(1652953380));
    }

    static VerifiableCredential vcExperianFraudMissingName() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(Collections.emptyList())
                        .address(List.of(ADDRESS_3))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_CRI_STUB_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                TEST_ISSUER_STAGING,
                Instant.ofEpochSecond(1704290386));
    }

    static VerifiableCredential vcFraudApplicableAuthoritativeSourceFailed() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .birthDate(List.of(createBirthDate("1959-08-23")))
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(
                                FRAUD_EVIDENCE_FAILED_APPLICABLE_AUTHORITATIVE_SOURCE_CHECK_DETAILS)
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://review-f.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcFraudAvailableAuthoritativeFailed() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .birthDate(List.of(createBirthDate("1959-08-23")))
                        .build();
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                TestVc.builder()
                        .evidence(
                                FRAUD_EVIDENCE_FAILED_AUTHORITATIVE_AVAILABLE_SOURCE_CHECK_DETAILS)
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://review-f.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829758));
    }

    static VerifiableCredential vcDrivingPermit() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .drivingPermit(List.of(DRIVING_PERMIT_DVA))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE_VRI_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDrivingPermitMissingDrivingPermit() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().address(List.of(ADDRESS_4)).build();
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE_VRI_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDrivingPermitEmptyDrivingPermit() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .drivingPermit(List.of())
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE_VRI_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDrivingPermitFailedChecks() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .drivingPermit(List.of(INVALID_DRIVING_PERMIT))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                TestVc.builder()
                        .evidence(DCMAW_FAILED_EVIDENCE)
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705468290));
    }

    static VerifiableCredential vcDrivingPermitNonDcmaw() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(null)
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(createBirthDate("1970-01-01")))
                        .drivingPermit(List.of(DRIVING_PERMIT_DVLA))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE_DATA_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://driving-license-cri.stubs.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static VerifiableCredential vcDrivingPermitNoCredentialSubjectProperty() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                TestVc.builder()
                        .credentialSubject(null)
                        .evidence(DCMAW_EVIDENCE_VRI_CHECK)
                        .type(
                                new String[] {
                                    VERIFIABLE_CREDENTIAL_TYPE, IDENTITY_CHECK_CREDENTIAL_TYPE
                                })
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDrivingPermitIncorrectType() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                TestVc.builder()
                        .type(new String[] {VERIFIABLE_CREDENTIAL_TYPE, ADDRESS_CREDENTIAL_TYPE})
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential generateNinoVc(
            TestVc.TestCredentialSubject credentialSubject, List<TestVc.TestEvidence> evidence) {
        return generateVerifiableCredential(
                "urn:uuid:51dfa9ac-8624-4b93-aa8f-99ed772ff0ec",
                NINO,
                TestVc.builder().evidence(evidence).credentialSubject(credentialSubject).build(),
                "https://review-xx.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static TestVc.TestEvidence testFailedNinoEvidence =
            TestVc.TestEvidence.builder()
                    .txn("e5b22348-c866-4b25-bb50-ca2106af7874")
                    .failedCheckDetails(List.of(Map.of("checkMethod", "data")))
                    .build();

    static VerifiableCredential vcNinoSuccessful() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .socialSecurityRecord(
                                List.of(createSocialSecurityRecordDetails("AA000003D")))
                        .build();

        var evidence =
                List.of(
                        TestVc.TestEvidence.builder()
                                .txn("e5b22348-c866-4b25-bb50-ca2106af7874")
                                .checkDetails(List.of(Map.of("checkMethod", "data")))
                                .build());
        return generateNinoVc(credentialSubject, evidence);
    }

    static VerifiableCredential vcNinoUnsuccessful() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(null)
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(createBirthDate("1970-01-01")))
                        .socialSecurityRecord(
                                List.of(createSocialSecurityRecordDetails("AA000003D")))
                        .build();

        var evidence = List.of(testFailedNinoEvidence);
        return generateNinoVc(credentialSubject, evidence);
    }

    static VerifiableCredential vcNinoMissingSocialSecurityRecord() {
        return generateNinoVc(
                TestVc.TestCredentialSubject.builder().build(),
                List.of(TestVc.TestEvidence.builder().build()));
    }

    static VerifiableCredential vcNinoEmptySocialSecurityRecord() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().socialSecurityRecord(List.of()).build();

        var evidence = List.of(testFailedNinoEvidence);

        return generateNinoVc(credentialSubject, evidence);
    }

    static VerifiableCredential vcNinoInvalidVcType() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                NINO,
                TestVc.builder()
                        .type(
                                new String[] {
                                    VERIFIABLE_CREDENTIAL_TYPE, RISK_ASSESSMENT_CREDENTIAL_TYPE
                                })
                        .build(),
                "https://ticf.stubs.account.gov.uk",
                Instant.ofEpochSecond(1704822570));
    }

    static VerifiableCredential vcTicf() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                TICF,
                TestVc.builder()
                        .credentialSubject(null)
                        .evidence(TICF_EVIDENCE)
                        .type(
                                new String[] {
                                    VERIFIABLE_CREDENTIAL_TYPE, RISK_ASSESSMENT_CREDENTIAL_TYPE
                                })
                        .build(),
                "https://ticf.stubs.account.gov.uk",
                Instant.ofEpochSecond(1704822570));
    }

    static VerifiableCredential vcTicfWithCi() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                TICF,
                TestVc.builder()
                        .credentialSubject(null)
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .type(RISK_ASSESSMENT_EVIDENCE_TYPE)
                                                .txn("963deeb5-a52c-4030-a69a-3184f77a4f18")
                                                .checkDetails(null)
                                                .ci(List.of("test"))
                                                .build()))
                        .type(
                                new String[] {
                                    VERIFIABLE_CREDENTIAL_TYPE, RISK_ASSESSMENT_CREDENTIAL_TYPE
                                })
                        .build(),
                "https://ticf.stubs.account.gov.uk",
                Instant.ofEpochSecond(1704822570));
    }

    static VerifiableCredential vcVerificationM1a() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(createBirthDate("1970-01-01")))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                Cri.EXPERIAN_KBV,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("abc1234")
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://review-k.integration.account.gov.uk",
                Instant.ofEpochSecond(1653403140));
    }

    VerifiableCredential M1B_DCMAW_VC =
            generateVerifiableCredential(
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

    VerifiableCredential DCMAW_PASSPORT_VC =
            generateVerifiableCredential(
                    "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                    DCMAW,
                    TestVc.builder()
                            .evidence(
                                    List.of(
                                            TestVc.TestEvidence.builder()
                                                    .txn("bcd2346")
                                                    .strengthScore(4)
                                                    .validityScore(2)
                                                    .verificationScore(3)
                                                    .build()))
                            .credentialSubject(
                                    TestVc.TestCredentialSubject.builder()
                                            .name(List.of(MORGAN_SARAH_MEREDYTH_NAME))
                                            .address(List.of(ADDRESS_4))
                                            .passport(PASSPORT_DETAILS)
                                            .build())
                            .build(),
                    Instant.ofEpochSecond(1705986521));

    static VerifiableCredential vcDcmawAsyncDl() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(List.of((MORGAN_SARAH_MEREDYTH_NAME)))
                        .address(List.of(ADDRESS_4))
                        .birthDate(List.of(createBirthDate("1970-01-01")))
                        .drivingPermit(List.of(DRIVING_PERMIT_DVA))
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DCMAW_ASYNC,
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE_VRI_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://dcmaw-async.stubs.account.gov.uk/async/credential",
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawAsyncPassport() {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(List.of((MORGAN_SARAH_MEREDYTH_NAME)))
                        .address(List.of(ADDRESS_4))
                        .passport(PASSPORT_DETAILS)
                        .build();
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DCMAW_ASYNC,
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("bcd2346")
                                                .strengthScore(4)
                                                .validityScore(2)
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
                        .credentialSubject(credentialSubject)
                        .build(),
                "https://dcmaw-async.stubs.account.gov.uk/async/credential",
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcF2fM1a() {
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
                        .passport(PASSPORT_DETAILS)
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
                        .passport(PASSPORT_DETAILS)
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
                TestVc.builder().evidence(SUCCESSFUL_EVIDENCE).build(),
                "https://review-p.staging.account.gov.uk",
                "not-a-vot",
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcNullVot() throws Exception {
        return generateVerifiableCredential(
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                null,
                TestVc.builder().evidence(SUCCESSFUL_EVIDENCE).build(),
                "https://review-p.staging.account.gov.uk",
                null,
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }
}
