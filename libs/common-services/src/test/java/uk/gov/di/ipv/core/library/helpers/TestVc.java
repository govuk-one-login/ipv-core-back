package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.ResidencePermitDetails;
import uk.gov.di.model.SocialSecurityRecordDetails;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.IDENTITY_CHECK_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME_PARTS;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator.createBirthDate;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.NamePartGenerator.createNamePart;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Jacksonized
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TestVc {

    public static final String DEFAULT_DOB = "1965-07-08";

    @Builder.Default
    private String[] type = {VERIFIABLE_CREDENTIAL_TYPE, IDENTITY_CHECK_CREDENTIAL_TYPE};

    @Builder.Default
    private TestCredentialSubject credentialSubject = TestCredentialSubject.builder().build();

    @Builder.Default private List<TestEvidence> evidence = List.of(TestEvidence.builder().build());

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class TestCredentialSubject {
        @Builder.Default
        private List<Map<String, List<NamePart>>> name =
                List.of(
                        Map.of(
                                VC_NAME_PARTS,
                                List.of(
                                        createNamePart("KENNETH", NamePart.NamePartType.GIVEN_NAME),
                                        createNamePart(
                                                "DECERQUEIRA",
                                                NamePart.NamePartType.FAMILY_NAME))));

        @Builder.Default private List<BirthDate> birthDate = List.of(createBirthDate(DEFAULT_DOB));
        private List<PassportDetails> passport;
        private List<Object> address;
        private List<SocialSecurityRecordDetails> socialSecurityRecord;
        private List<DrivingPermitDetails> drivingPermit;
        private List<ResidencePermitDetails> residencePermit;
        private List<Object> idCard;
    }

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class TestEvidence {
        @Builder.Default private String type = IDENTITY_CHECK_EVIDENCE_TYPE;
        @Builder.Default private String txn = "1c04edf0-a205-4585-8877-be6bd1776a39";
        private Integer strengthScore;
        private Integer validityScore;
        private Integer verificationScore;
        @Builder.Default private List<Object> ci = Collections.emptyList();
        private Integer identityFraudScore;
        private Integer activityHistoryScore;

        @Builder.Default
        private List<Object> checkDetails =
                List.of(
                        Map.of("checkMethod", "data", "dataCheck", "cancelled_check"),
                        Map.of("checkMethod", "data", "dataCheck", "record_check"));

        private List<Object> failedCheckDetails;
    }
}
