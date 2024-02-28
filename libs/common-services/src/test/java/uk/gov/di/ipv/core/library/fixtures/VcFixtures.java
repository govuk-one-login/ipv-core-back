package uk.gov.di.ipv.core.library.fixtures;

import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.helpers.TestVc;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.CRI_STUB_CHECK_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.RISK_ASSESSMENT_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.RISK_ASSESSMENT_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_FAMILY_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_GIVEN_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME_PARTS;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;

public interface VcFixtures {
    List<TestVc.TestEvidence> SUCCESSFUL_EVIDENCE =
            List.of(TestVc.TestEvidence.builder().strengthScore(4).validityScore(2).build());
    List<TestVc.TestEvidence> UNSUCCESSFUL_EVIDENCE =
            List.of(TestVc.TestEvidence.builder().strengthScore(4).validityScore(0).build());
    List<TestVc.TestEvidence> TEST_CI_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .strengthScore(4)
                            .validityScore(2)
                            .ci(List.of("test"))
                            .ciReasons(List.of(Map.of("ci", "testValue", "reason", "testReason")))
                            .build());

    List<TestVc.TestEvidence> FRAUD_EVIDENCE =
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

    List<TestVc.TestEvidence> FRAUD_EVIDENCE_SCORE_ONE =
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
                            .type(CRI_STUB_CHECK_EVIDENCE_TYPE)
                            .txn("some-uuid")
                            .identityFraudScore(1)
                            .build());

    List<TestVc.TestEvidence> DCMAW_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .txn("bcd2346")
                            .strengthScore(3)
                            .validityScore(2)
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

    List<TestVc.TestEvidence> DCMAW_EVIDENCE_2 =
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
                            .build());
    Map<String, String> ADDRESS_1 =
            Map.ofEntries(
                    Map.entry("validFrom", "2000-01-01"),
                    Map.entry("uprn", "100120012077"),
                    Map.entry("addressRegion", "Illinois"),
                    Map.entry("streetAddress", "35 Idsworth Road"),
                    Map.entry("addressLocality", "Sheffield"),
                    Map.entry("type", "PostalAddress"),
                    Map.entry("addressCountry", "GB"),
                    Map.entry("organizationName", "Software Ltd"),
                    Map.entry("subBuildingName", ""),
                    Map.entry("buildingNumber", "8"),
                    Map.entry("buildingName", ""),
                    Map.entry("postalCode", "S5 6UN"));

    Map<String, String> ADDRESS_2 =
            Map.ofEntries(
                    Map.entry("uprn", "100120012077"),
                    Map.entry("subBuildingName", ""),
                    Map.entry("buildingNumber", "8"),
                    Map.entry("buildingName", "221B"),
                    Map.entry("streetName", "MILTON ROAD"),
                    Map.entry("addressLocality", "Milton Keynes"),
                    Map.entry("postalCode", "MK15 5BX"),
                    Map.entry("addressCountry", "GB"),
                    Map.entry("validFrom", "2024-01-01"));
    Map<String, String> ADDRESS_3 =
            Map.ofEntries(
                    Map.entry("uprn", "100120012077"),
                    Map.entry("buildingNumber", "8"),
                    Map.entry("buildingName", ""),
                    Map.entry("streetName", "HADLEY ROAD"),
                    Map.entry("addressLocality", "BATH"),
                    Map.entry("postalCode", "BA2 5AA"),
                    Map.entry("addressCountry", "GB"),
                    Map.entry("validUntil", "2000-01-01"));

    Map<String, String> ADDRESS_4 =
            Map.ofEntries(
                    Map.entry("uprn", "10022812929"),
                    Map.entry("organisationName", "FINCH GROUP"),
                    Map.entry("subBuildingName", "UNIT 2B"),
                    Map.entry("buildingNumber ", "16"),
                    Map.entry("buildingName", "COY POND BUSINESS PARK"),
                    Map.entry("dependentStreetName", "KINGS PARK"),
                    Map.entry("streetName", "BIG STREET"),
                    Map.entry("doubleDependentAddressLocality", "SOME DISTRICT"),
                    Map.entry("dependentAddressLocality", "LONG EATON"),
                    Map.entry("addressLocality", "GREAT MISSENDEN"),
                    Map.entry("postalCode", "HP16 0AL"),
                    Map.entry("addressCountry", "GB"));

    List<Object> MULTIPLE_ADDRESSES_VALID =
            List.of(
                    ADDRESS_3,
                    Map.ofEntries(
                            Map.entry("uprn", "100120012077"),
                            Map.entry("buildingNumber", "3"),
                            Map.entry("buildingName", ""),
                            Map.entry("streetName", "STOCKS HILL"),
                            Map.entry("addressLocality", "HARRINGTON"),
                            Map.entry("postalCode", "CA14 5PH"),
                            Map.entry("addressCountry", "GB"),
                            Map.entry("validFrom", "2011-01-01")),
                    Map.ofEntries(
                            Map.entry("uprn", "100120012077"),
                            Map.entry("buildingNumber", "24"),
                            Map.entry("buildingName", ""),
                            Map.entry("streetName", "SOME STREET"),
                            Map.entry("addressLocality", "SOME LOCALITY"),
                            Map.entry("postalCode", "TE5 7ER"),
                            Map.entry("addressCountry", "GB"),
                            Map.entry("validUntil", "2011-01-01")));

    List<Object> MULTIPLE_ADDRESSES_NO_VALID_FROM =
            List.of(
                    ADDRESS_3,
                    Map.ofEntries(
                            Map.entry("uprn", "100120012077"),
                            Map.entry("buildingNumber", "3"),
                            Map.entry("buildingName", ""),
                            Map.entry("streetName", "STOCKS HILL"),
                            Map.entry("addressLocality", "HARRINGTON"),
                            Map.entry("postalCode", "CA14 5PH"),
                            Map.entry("addressCountry", "GB")),
                    Map.ofEntries(
                            Map.entry("uprn", "100120012077"),
                            Map.entry("buildingNumber", "24"),
                            Map.entry("buildingName", ""),
                            Map.entry("streetName", "SOME STREET"),
                            Map.entry("addressLocality", "SOME LOCALITY"),
                            Map.entry("postalCode", "TE5 7ER"),
                            Map.entry("addressCountry", "GB")));

    Map<String, List<NameParts>> ALICE_PARKER_NAME =
            Map.of(
                    VC_NAME_PARTS,
                    List.of(
                            new NameParts("Alice", VC_GIVEN_NAME),
                            new NameParts("Jane", VC_GIVEN_NAME),
                            new NameParts("Parker", VC_FAMILY_NAME)));
    Map<String, List<NameParts>> MORGAN_SARAH_MEREDYTH_NAME =
            Map.of(
                    VC_NAME_PARTS,
                    List.of(
                            new NameParts("MORGAN", VC_GIVEN_NAME),
                            new NameParts("SARAH MEREDYTH", VC_FAMILY_NAME)));

    Map<String, List<NameParts>> MARY_WATSON_NAME =
            Map.of(
                    VC_NAME_PARTS,
                    List.of(
                            new NameParts("Mary", VC_GIVEN_NAME),
                            new NameParts("Watson", VC_FAMILY_NAME)));

    Map<String, Object> DRIVING_PERMIT =
            Map.of(
                    "personalNumber", "MORGA753116SM9IJ",
                    "expiryDate", "2042-10-01",
                    "issuedBy", "DVA",
                    "issueNumber", 123456,
                    "issueDate", "2018-04-19");

    Map<String, Object> DRIVING_PERMIT_2 =
            Map.of(
                    "personalNumber", "PARKE710112PBFGA",
                    "expiryDate", "2032-02-02",
                    "issuedBy", "DVLA",
                    "issueDate", "2005-02-02");

    Map<String, Object> INVALID_DRIVING_PERMIT =
            Map.of(
                    "personalNumber", "MORGA753116SM9IJ",
                    "expiryDate", "2042-10-01");

    static String vcPassportNonDcmawSuccessful() throws Exception {
        return generateVerifiableCredential(
                TestVc.builder().evidence(SUCCESSFUL_EVIDENCE).build(),
                Instant.ofEpochSecond(1705986521));
    }

    static String vcPassportM1aFailed() throws Exception {
        return generateVerifiableCredential(
                TestVc.builder().evidence(UNSUCCESSFUL_EVIDENCE).build(),
                Instant.ofEpochSecond(1705986521));
    }

    static String vcPassportM1aWithCI() throws Exception {
        return generateVerifiableCredential(
                TestVc.builder().evidence(TEST_CI_EVIDENCE).build(),
                Instant.ofEpochSecond(1705986521));
    }

    static String vcPassportM1aMissingEvidence() throws Exception {
        return generateVerifiableCredential(
                TestVc.builder().evidence(Collections.emptyList()).build(),
                Instant.ofEpochSecond(1705986521));
    }

    static String vcPassportMissingName() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().name(Collections.emptyList()).build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static String vcPassportMissingBirthDate() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().birthDate(Collections.emptyList()).build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static String vcPassportInvalidBirthDate() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .birthDate(List.of(new BirthDate("invalid")))
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static String vcPassportMissingPassport() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().passport(Collections.emptyList()).build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build());
    }

    static String vcAddressOne() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().address(List.of(ADDRESS_1)).build();
        return generateVerifiableCredential(
                TestVc.builder().credentialSubject(credentialSubject).build());
    }

    static String vcAddressTwo() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(List.of(ALICE_PARKER_NAME))
                        .address(List.of(ADDRESS_2))
                        .passport(Collections.emptyList())
                        .build();
        return generateVerifiableCredential(
                TestVc.builder().credentialSubject(credentialSubject).build());
    }

    static String vcAddressM1a() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(null)
                        .address(List.of(ADDRESS_3))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder().credentialSubject(credentialSubject).evidence(null).build(),
                "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345",
                "https://review-a.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829720));
    }

    static String vcAddressMultipleAddresses() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(null)
                        .address(MULTIPLE_ADDRESSES_VALID)
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder().credentialSubject(credentialSubject).evidence(null).build(),
                "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345",
                "https://review-a.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829720));
    }

    static String vcAddressMultipleAddressesNoValidFrom() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(null)
                        .address(MULTIPLE_ADDRESSES_NO_VALID_FROM)
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder().credentialSubject(credentialSubject).evidence(null).build(),
                "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345",
                "https://review-a.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829720));
    }

    static String vcExperianFraudM1a() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .birthDate(List.of(new BirthDate("1959-08-23")))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE)
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345",
                "https://review-f.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829758));
    }

    static String vcExperianFraudFailed() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .birthDate(List.of(new BirthDate("1959-08-23")))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(FRAUD_FAILED_EVIDENCE)
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345",
                "https://review-f.integration.account.gov.uk",
                Instant.ofEpochSecond(1658829758));
    }

    static String vcExperianFraudScoreOne() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_3))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_SCORE_ONE)
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                "https://review-f.staging.account.gov.uk",
                Instant.ofEpochSecond(1704290386));
    }

    static String vcExperianFraudScoreTwo() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(
                                List.of(
                                        Map.of(
                                                VC_NAME_PARTS,
                                                List.of(new NameParts("Chris", VC_GIVEN_NAME)))))
                        .address(List.of(Map.of("type", "PostalAddress", "postalCode", "LE12 9BN")))
                        .birthDate(List.of(new BirthDate("1984-09-28")))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_CRI_STUB_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                "user-id",
                "https://review-f.staging.account.gov.uk",
                Instant.ofEpochSecond(1652953380));
    }

    static String vcExperianFraudMissingName() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(Collections.emptyList())
                        .address(List.of(ADDRESS_3))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(FRAUD_EVIDENCE_CRI_STUB_CHECK)
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                "https://review-f.staging.account.gov.uk",
                Instant.ofEpochSecond(1704290386));
    }

    static String vcDrivingPermit() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .drivingPermit(List.of(DRIVING_PERMIT))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE)
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static String vcDrivingPermitMissingDrivingPermit() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE)
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static String vcDrivingPermitFailedChecks() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .drivingPermit(List.of(INVALID_DRIVING_PERMIT))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(DCMAW_FAILED_EVIDENCE)
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705468290));
    }

    static String vcDrivingPermitNonDcmaw() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(null)
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(new BirthDate("1970-01-01")))
                        .drivingPermit(List.of(DRIVING_PERMIT_2))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(DCMAW_EVIDENCE_2)
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                "https://driving-license-cri.stubs.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static String vcNinoSuccessful() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(null)
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(new BirthDate("1970-01-01")))
                        .socialSecurityRecord(List.of(Map.of("personalNumber", "AA000003D")))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("e5b22348-c866-4b25-bb50-ca2106af7874")
                                                .checkDetails(
                                                        List.of(Map.of("checkMethod", "data")))
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:51dfa9ac-8624-4b93-aa8f-99ed772ff0ec",
                "https://review-xx.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static String vcNinoUnsuccessful() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(null)
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(new BirthDate("1970-01-01")))
                        .socialSecurityRecord(List.of(Map.of("personalNumber", "AA000003D")))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("e5b22348-c866-4b25-bb50-ca2106af7874")
                                                .failedCheckDetails(
                                                        List.of(Map.of("checkMethod", "data")))
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:51dfa9ac-8624-4b93-aa8f-99ed772ff0ec",
                "https://review-xx.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static String vcNinoMissingSocialSecurityRecord() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(null)
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(new BirthDate("1970-01-01")))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("e5b22348-c866-4b25-bb50-ca2106af7874")
                                                .failedCheckDetails(
                                                        List.of(Map.of("checkMethod", "data")))
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:51dfa9ac-8624-4b93-aa8f-99ed772ff0ec",
                "https://review-xx.account.gov.uk",
                Instant.ofEpochSecond(1697097326));
    }

    static String vcTicf() throws Exception {
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(null)
                        .evidence(TICF_EVIDENCE)
                        .type(
                                new String[] {
                                    VERIFIABLE_CREDENTIAL_TYPE, RISK_ASSESSMENT_CREDENTIAL_TYPE
                                })
                        .build(),
                "urn:uuid:d1823066-2137-4380-b0ba-4b61947e08e6",
                "https://ticf.stubs.account.gov.uk",
                Instant.ofEpochSecond(1704822570));
    }

    static String vcVerificationM1a() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .address(List.of(ADDRESS_4))
                        .name(List.of((ALICE_PARKER_NAME)))
                        .birthDate(List.of(new BirthDate("1970-01-01")))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("abc1234")
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                "test-subject",
                "https://review-k.integration.account.gov.uk",
                Instant.ofEpochSecond(1653403140));
    }

    static String vcDcmawM1b() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(List.of(MORGAN_SARAH_MEREDYTH_NAME))
                        .address(List.of(ADDRESS_4))
                        .drivingPermit(List.of(DRIVING_PERMIT))
                        .passport(null)
                        .build();
        return generateVerifiableCredential(
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
                                                                        3)))
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1705986521));
    }

    static String vcF2fM1a() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(List.of(MARY_WATSON_NAME))
                        .passport(
                                List.of(
                                        Map.of(
                                                "expiryDate",
                                                "2030-01-01",
                                                "documentNumber",
                                                "824159121")))
                        .build();
        return generateVerifiableCredential(
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

    static String vcF2fBrp() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(
                                List.of(
                                        Map.of(
                                                VC_NAME_PARTS,
                                                List.of(new NameParts("Chris", VC_GIVEN_NAME)))))
                        .birthDate(List.of(new BirthDate("1984-09-28")))
                        .passport(null)
                        .residencePermit(
                                List.of(
                                        Map.of(
                                                "icaoIssuerCode",
                                                "UTO",
                                                "documentType",
                                                "CR",
                                                "documentNumber",
                                                "AX66K69P2",
                                                "expiryDate",
                                                "2030-07-13")))
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("some-uuid")
                                                .type(CRI_STUB_CHECK_EVIDENCE_TYPE)
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1652953080));
    }

    static String vcF2fIdCard() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .name(
                                List.of(
                                        Map.of(
                                                VC_NAME_PARTS,
                                                List.of(new NameParts("Chris", VC_GIVEN_NAME)))))
                        .birthDate(List.of(new BirthDate("1984-09-28")))
                        .passport(null)
                        .idCard(
                                List.of(
                                        Map.of(
                                                "icaoIssuerCode",
                                                "NLD",
                                                "documentNumber",
                                                "SPEC12031",
                                                "expiryDate",
                                                "2031-08-02",
                                                "issueDate",
                                                "2021-08-02")))
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(
                                List.of(
                                        TestVc.TestEvidence.builder()
                                                .txn("some-uuid")
                                                .type(CRI_STUB_CHECK_EVIDENCE_TYPE)
                                                .verificationScore(2)
                                                .build()))
                        .credentialSubject(credentialSubject)
                        .build(),
                Instant.ofEpochSecond(1652953080));
    }

    static String vcMissingCredentialSubject() throws Exception {
        return generateVerifiableCredential(TestVc.builder().credentialSubject(null).build());
    }

    static String vcHmrcMigration() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .socialSecurityRecord(List.of(Map.of("personalNumber", "AB123456C")))
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
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(List.of(evidence))
                        .build(),
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                "https://orch.stubs.account.gov.uk/migration/v1",
                Vot.PCL250.toString(),
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static String vcHmrcMigrationNoEvidence() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder()
                        .socialSecurityRecord(List.of(Map.of("personalNumber", "AB123456C")))
                        .build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .evidence(Collections.emptyList())
                        .credentialSubject(credentialSubject)
                        .build(),
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                "https://orch.stubs.account.gov.uk/migration/v1",
                Vot.PCL250.toString(),
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static String vcInvalidVot() throws Exception {
        return generateVerifiableCredential(
                TestVc.builder().evidence(SUCCESSFUL_EVIDENCE).build(),
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                "https://review-p.staging.account.gov.uk",
                "not-a-vot",
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static String vcNullVot() throws Exception {
        return generateVerifiableCredential(
                TestVc.builder().evidence(SUCCESSFUL_EVIDENCE).build(),
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                "https://review-p.staging.account.gov.uk",
                null,
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }
}
