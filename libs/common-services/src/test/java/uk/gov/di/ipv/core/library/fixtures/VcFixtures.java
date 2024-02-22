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
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_FAMILY_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_GIVEN_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME_PARTS;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;

public interface VcFixtures {
    List<TestVc.TestEvidence> SUCCESSFUL_EVIDENCE =
            List.of(TestVc.TestEvidence.builder().strengthScore(4).validityScore(2).build());
    List<TestVc.TestEvidence> UNSUCCESSFUL_EVIDENCE =
            List.of(TestVc.TestEvidence.builder().strengthScore(4).validityScore(0).build());
    List<TestVc.TestEvidence> D02_CI_EVIDENCE =
            List.of(
                    TestVc.TestEvidence.builder()
                            .strengthScore(4)
                            .validityScore(2)
                            .ci(List.of("DO2"))
                            .ciReasons(List.of(Map.of("ci", "D02", "reason", "NoMatchingRecord")))
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
                TestVc.builder().evidence(D02_CI_EVIDENCE).build(),
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
