package uk.gov.di.ipv.core.library.fixtures;

import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.helpers.TestVc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_STRENGTH;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_VALIDITY;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_TYPE;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;

public interface VcFixtures {
    List<Map<String, Object>> SUCCESSFUL_EVIDENCE =
            List.of(
                    Map.of(
                            VC_TYPE,
                            IDENTITY_CHECK_EVIDENCE_TYPE,
                            VC_EVIDENCE_TXN,
                            "6e61e5db-a175-4e16-af83-1ddfc5668e2b",
                            VC_EVIDENCE_STRENGTH,
                            4,
                            VC_EVIDENCE_VALIDITY,
                            2));

    static String vcPassportNonDcmawSuccessful() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build(),
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                "https://review-p.staging.account.gov.uk",
                Instant.ofEpochSecond(1705986521));
    }

    static String vcPassportMissingName() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().name(null).build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build(),
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                "https://review-p.staging.account.gov.uk");
    }

    static String vcPassportMissingBirthDate() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().birthDate(null).build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build(),
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                "https://review-p.staging.account.gov.uk");
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
                        .build(),
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                "https://review-p.staging.account.gov.uk");
    }

    static String vcPassportMissingPassport() throws Exception {
        TestVc.TestCredentialSubject credentialSubject =
                TestVc.TestCredentialSubject.builder().passport(null).build();
        return generateVerifiableCredential(
                TestVc.builder()
                        .credentialSubject(credentialSubject)
                        .evidence(SUCCESSFUL_EVIDENCE)
                        .build(),
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                "https://review-p.staging.account.gov.uk");
    }
}
