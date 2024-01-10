package uk.gov.di.ipv.core.library.gpg45.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;

import java.util.Comparator;
import java.util.List;
import java.util.function.Function;

@AllArgsConstructor
@Builder
@Getter
public class CredentialEvidenceItem {
    public static final String TICF_EVIDENCE_TYPE = "RiskAssessment";
    private String credentialIss;
    private Integer activityHistoryScore;
    private Integer identityFraudScore;
    private Integer strengthScore;
    private Integer validityScore;
    private Integer verificationScore;
    private List<CheckDetail> checkDetails;
    private List<CheckDetail> failedCheckDetails;
    private final List<String> ci;
    private String type;

    public CredentialEvidenceItem(EvidenceType evidenceType, int score, List<String> ci) {
        if (EvidenceType.ACTIVITY.equals(evidenceType)) {
            this.activityHistoryScore = score;
        } else if (EvidenceType.IDENTITY_FRAUD.equals(evidenceType)) {
            this.identityFraudScore = score;
        } else if (EvidenceType.VERIFICATION.equals(evidenceType)) {
            this.verificationScore = score;
        }
        this.ci = ci;
    }

    public CredentialEvidenceItem(int strengthScore, int validityScore, List<String> ci) {
        this.strengthScore = strengthScore;
        this.validityScore = validityScore;
        this.ci = ci;
    }

    public CredentialEvidenceItem(
            int strengthScore,
            int validityScore,
            int activityHistoryScore,
            int verificationScore,
            List<CheckDetail> checkDetails,
            List<CheckDetail> failedCheckDetails,
            List<String> ci) {
        this.strengthScore = strengthScore;
        this.validityScore = validityScore;
        this.activityHistoryScore = activityHistoryScore;
        this.verificationScore = verificationScore;
        this.checkDetails = checkDetails;
        this.failedCheckDetails = failedCheckDetails;
        this.ci = ci;
    }

    public EvidenceType getEvidenceType() throws UnknownEvidenceTypeException {
        if (isActivityHistory()) {
            return EvidenceType.ACTIVITY;
        } else if (isIdentityFraud()) {
            return EvidenceType.IDENTITY_FRAUD;
        } else if (isEvidence()) {
            return EvidenceType.EVIDENCE;
        } else if (isVerification()) {
            return EvidenceType.VERIFICATION;
        }

        if (isDcmaw()) {
            return EvidenceType.DCMAW;
        } else if (isF2F()) {
            return EvidenceType.F2F;
        } else if (isFraudWithActivity()) {
            return EvidenceType.FRAUD_WITH_ACTIVITY;
        } else if (isNino()) {
            return EvidenceType.NINO;
        } else if (isTicf()) {
            return EvidenceType.TICF;
        } else {
            throw new UnknownEvidenceTypeException();
        }
    }

    public Gpg45Scores.Evidence getEvidenceScore() {
        return new Gpg45Scores.Evidence(getStrengthScore(), getValidityScore());
    }

    public boolean hasContraIndicators() {
        return ci != null && !ci.isEmpty();
    }

    private boolean isActivityHistory() {
        return activityHistoryScore != null
                && identityFraudScore == null
                && strengthScore == null
                && validityScore == null
                && verificationScore == null;
    }

    private boolean isIdentityFraud() {
        return identityFraudScore != null
                && activityHistoryScore == null
                && strengthScore == null
                && validityScore == null
                && verificationScore == null;
    }

    private boolean isFraudWithActivity() {
        return identityFraudScore != null
                && activityHistoryScore != null
                && strengthScore == null
                && validityScore == null
                && verificationScore == null;
    }

    private boolean isEvidence() {
        return strengthScore != null
                && validityScore != null
                && activityHistoryScore == null
                && identityFraudScore == null
                && verificationScore == null
                && checkDetails == null
                && failedCheckDetails == null;
    }

    private boolean isVerification() {
        return verificationScore != null
                && activityHistoryScore == null
                && identityFraudScore == null
                && strengthScore == null
                && validityScore == null;
    }

    private boolean isDcmaw() {
        return strengthScore != null
                && validityScore != null
                && identityFraudScore == null
                && verificationScore == null
                && (checkDetails != null || failedCheckDetails != null);
    }

    private boolean isF2F() {
        return strengthScore != null
                && validityScore != null
                && identityFraudScore == null
                && verificationScore != null
                && (checkDetails != null || failedCheckDetails != null);
    }

    private boolean isNino() {
        return strengthScore == null
                && validityScore == null
                && identityFraudScore == null
                && verificationScore == null
                && (checkDetails != null || failedCheckDetails != null);
    }

    private boolean isTicf() {
        return type != null && type.equals(TICF_EVIDENCE_TYPE);
    }

    @Getter
    public enum EvidenceType {
        ACTIVITY(
                Comparator.comparingInt(CredentialEvidenceItem::getActivityHistoryScore),
                CredentialEvidenceItem::getActivityHistoryScore),
        IDENTITY_FRAUD(
                Comparator.comparingInt(CredentialEvidenceItem::getIdentityFraudScore),
                CredentialEvidenceItem::getIdentityFraudScore),
        EVIDENCE(null, null),
        VERIFICATION(
                Comparator.comparingInt(CredentialEvidenceItem::getVerificationScore),
                CredentialEvidenceItem::getVerificationScore),
        DCMAW(null, null),
        F2F(null, null),
        NINO(null, null),
        FRAUD_WITH_ACTIVITY(null, null),
        TICF(null, null);

        public final Comparator<CredentialEvidenceItem> comparator;
        public final Function<CredentialEvidenceItem, Integer> scoreGetter;

        EvidenceType(
                Comparator<CredentialEvidenceItem> comparator,
                Function<CredentialEvidenceItem, Integer> scoreGetter) {
            this.comparator = comparator;
            this.scoreGetter = scoreGetter;
        }
    }

    public void setCredentialIss(String credentialIss) {
        this.credentialIss = credentialIss;
    }
}
