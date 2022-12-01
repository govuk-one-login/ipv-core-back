package uk.gov.di.ipv.core.library.domain.gpg45.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;

import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.function.ToIntFunction;

@Getter
public class CredentialEvidenceItem {
    private String credentialIss;
    private Integer activityHistoryScore;
    private Integer identityFraudScore;
    private Integer strengthScore;
    private Integer validityScore;
    private Integer verificationScore;
    private List<DcmawCheckMethod> checkDetails;
    private List<DcmawCheckMethod> failedCheckDetails;
    private List<String> ci;

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
            List<DcmawCheckMethod> checkDetails,
            List<DcmawCheckMethod> failedCheckDetails,
            List<String> ci) {
        this.strengthScore = strengthScore;
        this.validityScore = validityScore;
        this.activityHistoryScore = activityHistoryScore;
        this.verificationScore = verificationScore;
        this.checkDetails = checkDetails;
        this.failedCheckDetails = failedCheckDetails;
        this.ci = ci;
    }

    public EvidenceType getType() throws UnknownEvidenceTypeException {
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

    private int numberOfContraIndicators() {
        if (ci != null) {
            return ci.size();
        }
        return 0;
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

    @Getter
    public enum EvidenceType {
        ACTIVITY(
                generateComparator(CredentialEvidenceItem::getActivityHistoryScore),
                CredentialEvidenceItem::getActivityHistoryScore),
        IDENTITY_FRAUD(
                generateComparator(CredentialEvidenceItem::getIdentityFraudScore),
                CredentialEvidenceItem::getIdentityFraudScore),
        EVIDENCE(null, null),
        VERIFICATION(
                generateComparator(CredentialEvidenceItem::getVerificationScore),
                CredentialEvidenceItem::getVerificationScore),
        DCMAW(null, null);

        public final Comparator<CredentialEvidenceItem> comparator;
        public final Function<CredentialEvidenceItem, Integer> scoreGetter;

        EvidenceType(
                Comparator<CredentialEvidenceItem> comparator,
                Function<CredentialEvidenceItem, Integer> scoreGetter) {
            this.comparator = comparator;
            this.scoreGetter = scoreGetter;
        }

        private static Comparator<CredentialEvidenceItem> generateComparator(
                ToIntFunction<CredentialEvidenceItem> keyExtractor) {
            return Comparator.comparingInt(keyExtractor)
                    .thenComparing(
                            Comparator.comparingInt(
                                            CredentialEvidenceItem::numberOfContraIndicators)
                                    .reversed());
        }
    }

    public void setCredentialIss(String credentialIss) {
        this.credentialIss = credentialIss;
    }
}
