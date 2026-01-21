package uk.gov.di.ipv.core.library.fixtures;

import com.nimbusds.jose.jwk.KeyType;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.model.AddressAssertion;
import uk.gov.di.model.AddressCredential;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.CheckDetails;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.Intervention;
import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.RiskAssessment;
import uk.gov.di.model.RiskAssessmentCredential;
import uk.gov.di.model.SecurityCheck;
import uk.gov.di.model.SecurityCheckCredential;
import uk.gov.di.model.SocialSecurityRecordDetails;
import uk.gov.di.model.VerifiableCredentialType;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.domain.Cri.DWP_KBV;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.NINO;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.RISK_ASSESSMENT_EVIDENCE_TYPE;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.vocab.DrivingPermitDetailsGenerator.createDrivingPermitDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.IdCardDetailsGenerator.createIdCardDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.PassportDetailsGenerator.createPassportDetails;
import static uk.gov.di.ipv.core.library.helpers.vocab.PostalAddressGenerator.createPostalAddress;
import static uk.gov.di.ipv.core.library.helpers.vocab.ResidencePermitDetailsGenerator.createResidencePermitDetails;
import static uk.gov.di.model.NamePart.NamePartType.FAMILY_NAME;
import static uk.gov.di.model.NamePart.NamePartType.GIVEN_NAME;

public interface VcFixtures {
    String TEST_SUBJECT = "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345";
    String TEST_ISSUER_INTEGRATION = "https://review-a.integration.account.gov.uk";
    String DCMAW_ASYNC_ISSUER_BUILD = "https://dcmaw-async.stubs.account.gov.uk/async/credential";
    String DCMAW_ISSUER_STAGING = "https://review-b.staging.account.gov.uk";
    String DRIVING_PERMIT_ISSUER_STAGING = "https://review-d.staging.account.gov.uk";
    String F2F_ISSUER_STAGING = "https://review-o.staging.account.gov.uk";
    String FRAUD_ISSUER_STAGING = "https://review-f.staging.account.gov.uk";
    String FRAUD_ISSUER_INTEGRATION = "https://review-f.integration.account.gov.uk";
    String EXPERIAN_KBV_ISSUER_INTEGRATION = "https://review-k.integration.account.gov.uk";
    String DWP_KBV_ISSUER_STAGING = "https://gdskbvauth-test.financial-support.service.dwp.gov.uk";
    String PASSPORT_ISSUER_STAGING = "https://review-p.staging.account.gov.uk";
    String TICF_ISSUER = "https://ticf.stubs.account.gov.uk";
    String CIMIT_ISSUER = "https://cimit.stubs.account.gov.uk";
    String DEFAULT_DOB = "1965-07-08";
    Instant INSTANT_01_01_2099 = Instant.ofEpochSecond(4070908800L);
    Instant INSTANT_26_07_2022 = Instant.ofEpochSecond(1658829758L);

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
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
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

    private static AddressCredential vcClaimAddressValid(PostalAddress address) {
        return vcClaimAddressValid(List.of(address));
    }

    private static AddressCredential vcClaimAddressValid(List<PostalAddress> addresses) {
        return AddressCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.ADDRESS_CREDENTIAL))
                .withCredentialSubject(AddressAssertion.builder().withAddress(addresses).build())
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
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("bcd2346")
                                        .withActivityHistoryScore(1)
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

    private static IdentityCheckCredential vcClaimWebDrivingLicenceDvaExpired() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getCredentialSubject().setDrivingPermit(List.of(DRIVING_PERMIT_DVA_EXPIRED));
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
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
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

    private static IdentityCheckCredential vcClaimDwpKbv() {
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
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
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

    private static IdentityCheckCredential vcClaimDcmawDrivingPermitDvaNoEvidence() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(morganSarahMeredythName()))
                                .withBirthDate(
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
                                .withAddress(List.of(ADDRESS_4))
                                .withDrivingPermit(List.of(DRIVING_PERMIT_DVA))
                                .build())
                .build();
    }

    static IdentityCheckCredential vcClaimDcmawPassport() {
        var vcClaim = vcClaimDcmawDrivingPermitDva();
        vcClaim.getCredentialSubject().setDrivingPermit(null);
        vcClaim.getCredentialSubject().setPassport(passportDetails());
        vcClaim.getEvidence().get(0).setStrengthScore(4);

        return vcClaim;
    }

    static IdentityCheckCredential vcClaimDcmawPassportFailedNoBirthDate() {
        var vcClaim = vcClaimDcmawDrivingPermitDva();
        vcClaim.getCredentialSubject().setDrivingPermit(null);
        vcClaim.getCredentialSubject().setBirthDate(null);
        vcClaim.getCredentialSubject().setPassport(passportDetails());
        vcClaim.getEvidence().getFirst().setStrengthScore(0);

        return vcClaim;
    }

    private static IdentityCheckCredential vcClaimF2fPassportPhoto() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(maryWatsonName()))
                                .withPassport(
                                        List.of(
                                                createPassportDetails(
                                                        "824159121", null, "2030-01-01")))
                                .withBirthDate(
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withStrengthScore(4)
                                        .withValidityScore(2)
                                        .withVerificationScore(2)
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
                                                                .withTxn(
                                                                        "24929d38-420c-4ba9-b846-3005ee691e26")
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .PVR)
                                                                .withPhotoVerificationProcessLevel(
                                                                        3)
                                                                .withTxn(
                                                                        "24929d38-420c-4ba9-b846-3005ee691e26")
                                                                .build()))
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimF2fDrivingPermitDvaPhoto() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(morganSarahMeredythName()))
                                .withDrivingPermit(List.of(DRIVING_PERMIT_DVA))
                                .withBirthDate(
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withStrengthScore(4)
                                        .withValidityScore(2)
                                        .withVerificationScore(2)
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
                                                                .withTxn(
                                                                        "24929d38-420c-4ba9-b846-3005ee691e26")
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .PVR)
                                                                .withPhotoVerificationProcessLevel(
                                                                        2)
                                                                .withTxn(
                                                                        "24929d38-420c-4ba9-b846-3005ee691e26")
                                                                .build()))
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimF2fBrp() {
        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(kennethDecerqueiraName()))
                                .withBirthDate(
                                        List.of(BirthDate.builder().withValue(DEFAULT_DOB).build()))
                                .withResidencePermit(
                                        List.of(
                                                createResidencePermitDetails(
                                                        "AX66K69P2", "2030-07-13", "CR", "UTO")))
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("some-uuid")
                                        .withVerificationScore(2)
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .withDataCheck(
                                                                        CheckDetails.DataCheckType
                                                                                .CANCELLED_CHECK)
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .withDataCheck(
                                                                        CheckDetails.DataCheckType
                                                                                .RECORD_CHECK)
                                                                .build()))
                                        .build()))
                .build();
    }

    private static IdentityCheckCredential vcClaimF2fIdCard() {
        var vcClaim = vcClaimF2fBrp();
        vcClaim.getCredentialSubject().setResidencePermit(null);
        vcClaim.getCredentialSubject()
                .setIdCard(
                        List.of(
                                createIdCardDetails(
                                        "SPEC12031", "2031-08-02", "NLD", "2021-08-02")));

        return vcClaim;
    }

    private static SecurityCheckCredential vcClaimSecurityCheckNoCis() {
        return SecurityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.SECURITY_CHECK_CREDENTIAL,
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL))
                .withEvidence(
                        List.of(
                                SecurityCheck.builder()
                                        .withContraIndicator(List.of())
                                        .withType("SecurityCheck")
                                        .build()))
                .build();
    }

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

    static Name kennethDecerqueiraName() {
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

    private static Name maryWatsonName() {
        return Name.builder()
                .withNameParts(
                        List.of(
                                NamePart.builder().withType(GIVEN_NAME).withValue("Mary").build(),
                                NamePart.builder()
                                        .withType(FAMILY_NAME)
                                        .withValue("Watson")
                                        .build()))
                .build();
    }

    DrivingPermitDetails DRIVING_PERMIT_DVA =
            createDrivingPermitDetails("MORGA753116SM9IJ", "2042-10-01", "DVA", "2018-04-19");

    DrivingPermitDetails DRIVING_PERMIT_DVA_EXPIRED =
            createDrivingPermitDetails("MORGA753116SM9IJ", "2020-10-01", "DVA", "2018-04-19");

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
                PASSPORT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportSuccessfulWithRsaKeyType() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaimWebPassportValid(),
                PASSPORT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521),
                KeyType.RSA);
    }

    static VerifiableCredential vcWebPassportM1aFailed() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        var evidence = vcClaim.getEvidence().get(0);
        evidence.setValidityScore(0);
        evidence.setVerificationScore(0);

        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaim,
                PASSPORT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportM1aWithCI() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getEvidence().get(0).setCi(List.of("test"));
        vcClaim.getEvidence().get(0).setValidityScore(0);

        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaim,
                PASSPORT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportM1aWithCiButValidity2() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getEvidence().get(0).setCi(List.of("test"));

        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaim,
                PASSPORT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportM1aMissingEvidence() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.setEvidence(Collections.emptyList());

        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaim,
                PASSPORT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebPassportMissingName() {
        IdentityCheckCredential vcClaim = vcClaimWebPassportValid();
        vcClaim.getCredentialSubject().setName(Collections.emptyList());

        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.PASSPORT,
                vcClaim,
                PASSPORT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
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

    private static VerifiableCredential generateAddressVc(AddressCredential vcClaim) {
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
                INSTANT_01_01_2099);
    }

    static VerifiableCredential vcExperianFraudM1aExpired() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                Cri.EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                INSTANT_26_07_2022);
    }

    static VerifiableCredential vcExperianFraudEvidenceFailed() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore0(),
                FRAUD_ISSUER_INTEGRATION,
                INSTANT_01_01_2099);
    }

    static VerifiableCredential vcExperianFraudScoreTwo() {
        return generateVerifiableCredential(
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore2(),
                FRAUD_ISSUER_STAGING,
                INSTANT_01_01_2099);
    }

    static VerifiableCredential vcExperianFraudExpired() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                INSTANT_26_07_2022);
    }

    static VerifiableCredential vcExperianFraudNotExpired() {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                INSTANT_01_01_2099);
    }

    static VerifiableCredential vcExperianFraudScoreOne() {
        return generateVerifiableCredential(
                "user-id",
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_STAGING,
                INSTANT_01_01_2099);
    }

    static VerifiableCredential vcExperianFraud(Instant nbf) {
        return generateVerifiableCredential(
                TEST_SUBJECT,
                EXPERIAN_FRAUD,
                vcClaimExperianFraudScore1(),
                FRAUD_ISSUER_INTEGRATION,
                nbf);
    }

    static VerifiableCredential vcExperianFraudMissingName() {
        var vcClaim = vcClaimExperianFraudScore1();
        vcClaim.getCredentialSubject().setName(Collections.emptyList());

        return generateVerifiableCredential(
                "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092",
                EXPERIAN_FRAUD,
                vcClaim,
                FRAUD_ISSUER_STAGING,
                INSTANT_01_01_2099);
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
                INSTANT_01_01_2099);
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
                INSTANT_01_01_2099);
    }

    static VerifiableCredential vcWebDrivingPermitDvaValid() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaimWebDrivingLicenceDva(),
                DRIVING_PERMIT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitDvaExpired() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaimWebDrivingLicenceDvaExpired(),
                DRIVING_PERMIT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitMissingDrivingPermit() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getCredentialSubject().setDrivingPermit(null);

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                DRIVING_PERMIT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitEmptyDrivingPermit() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getCredentialSubject().setDrivingPermit(Collections.emptyList());

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                DRIVING_PERMIT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcWebDrivingPermitFailedChecks() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.getEvidence().get(0).setCi(List.of("testCI"));
        vcClaim.getEvidence().get(0).setValidityScore(0);

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                DRIVING_PERMIT_ISSUER_STAGING,
                Instant.ofEpochSecond(1705468290));
    }

    static VerifiableCredential vcWebDrivingPermitDvlaValid() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaimWebDrivingLicenceDvla(),
                DRIVING_PERMIT_ISSUER_STAGING,
                Instant.ofEpochSecond(1697097326));
    }

    static VerifiableCredential vcWebDrivingPermitNoCredentialSubjectProperty() {
        var vcClaim = vcClaimWebDrivingLicenceDvla();
        vcClaim.setCredentialSubject(null);

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DRIVING_LICENCE,
                vcClaim,
                DRIVING_PERMIT_ISSUER_STAGING,
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
                DRIVING_PERMIT_ISSUER_STAGING,
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

    static VerifiableCredential generateTicfVcWithIntervention(Intervention intervention) {
        var vcClaim = vcClaimTicf();
        vcClaim.getEvidence().get(0).setIntervention(intervention);

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

    static VerifiableCredential vcDwpKbv() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DWP_KBV,
                vcClaimDwpKbv(),
                DWP_KBV_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawDrivingPermitDvaM1b() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimDcmawDrivingPermitDva(),
                DCMAW_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawDrivingPermitDvaExpired() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimWebDrivingLicenceDvaExpired(),
                DCMAW_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDrivingPermitNullNbf() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimWebDrivingLicenceDvaExpired(),
                DCMAW_ISSUER_STAGING,
                null);
    }

    static VerifiableCredential vcDcmawDrivingPermitDvaExpiredSameDayAsNbf() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimWebDrivingLicenceDvaExpired(), // Expiry date is 2020-10-01
                DCMAW_ISSUER_STAGING,
                Instant.ofEpochSecond(1601555400)); // NBF is set to 2020-10-01T13:30:00
    }

    static VerifiableCredential vcDcmawPassport() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimDcmawPassport(),
                DCMAW_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawFailedPassport() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimDcmawPassportFailedNoBirthDate(),
                DCMAW_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawDvaNoEvidence() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimDcmawDrivingPermitDvaNoEvidence(),
                DCMAW_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawAsyncDrivingPermitDva() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DCMAW_ASYNC,
                vcClaimDcmawDrivingPermitDva(),
                DCMAW_ASYNC_ISSUER_BUILD,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawAsyncDrivingPermitDvaFailedChecks() {
        var vcClaim = vcClaimDcmawDrivingPermitDva();
        vcClaim.getEvidence().get(0).setCi(List.of("testCI"));
        vcClaim.getEvidence().get(0).setValidityScore(0);

        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DCMAW_ASYNC,
                vcClaim,
                DCMAW_ASYNC_ISSUER_BUILD,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcDcmawAsyncPassport() {
        return generateVerifiableCredential(
                "urn:uuid:e4999e16-b95e-4abe-8615-e0ef763353cc",
                DCMAW_ASYNC,
                vcClaimDcmawPassport(),
                DCMAW_ASYNC_ISSUER_BUILD,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcF2fPassportPhotoM1a() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                vcClaimF2fPassportPhoto(),
                F2F_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcF2fDrivingPermitDvaPhotoM1a() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                DCMAW,
                vcClaimF2fDrivingPermitDvaPhoto(),
                DCMAW_ISSUER_STAGING,
                Instant.ofEpochSecond(1705986521));
    }

    static VerifiableCredential vcF2fBrp() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                vcClaimF2fBrp(),
                F2F_ISSUER_STAGING,
                Instant.ofEpochSecond(1652953080));
    }

    static VerifiableCredential vcF2fIdCard() {
        return generateVerifiableCredential(
                "urn:uuid:01a44342-e643-4ca9-8306-a8e044092fb0",
                F2F,
                vcClaimF2fIdCard(),
                F2F_ISSUER_STAGING,
                Instant.ofEpochSecond(1652953080));
    }

    static VerifiableCredential vcNinoIdentityCheckL1a() {
        return generateVerifiableCredential(TEST_SUBJECT, NINO, vcClaimNinoIdentityCheck());
    }

    static VerifiableCredential vcP2Vot() {
        return generateVerifiableCredential(
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                Cri.PASSPORT,
                vcClaimWebPassportValid(),
                PASSPORT_ISSUER_STAGING,
                Vot.P2.name(),
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcInvalidVot() {
        return generateVerifiableCredential(
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                Cri.PASSPORT,
                vcClaimWebPassportValid(),
                PASSPORT_ISSUER_STAGING,
                "not-a-vot",
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcNullVot() {
        return generateVerifiableCredential(
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                Cri.PASSPORT,
                vcClaimWebPassportValid(),
                PASSPORT_ISSUER_STAGING,
                null,
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }

    static VerifiableCredential vcSecurityCheckNoCis() {
        return generateVerifiableCredential(
                "urn:uuid:811cefe0-7db6-48ad-ad89-0b93d2259980",
                Cri.CIMIT,
                vcClaimSecurityCheckNoCis(),
                CIMIT_ISSUER,
                null,
                "urn:uuid:db2481c0-8131-4ac2-b4d6-904c7de71a27",
                "https://hmrc.gov.uk/trustmark");
    }
}
