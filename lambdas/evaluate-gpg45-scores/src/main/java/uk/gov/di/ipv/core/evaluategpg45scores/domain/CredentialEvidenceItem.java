package uk.gov.di.ipv.core.evaluategpg45scores.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.evaluategpg45scores.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores;

import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.function.ToIntFunction;

import static uk.gov.di.ipv.core.evaluategpg45scores.validation.FraudEvidenceValidator.A01;

@Getter
public class CredentialEvidenceItem {
    private Integer activityScore;
    private Integer identityFraudScore;
    private Integer strengthScore;
    private Integer validityScore;
    private Integer verificationScore;
    private List<String> ci;

    public EvidenceType getType() throws UnknownEvidenceTypeException {
        if (isActivity()) {
            return EvidenceType.ACTIVITY;
        } else if (isIdentityFraud()) {
            return EvidenceType.IDENTITY_FRAUD;
        } else if (isEvidence()) {
            return EvidenceType.EVIDENCE;
        } else if (isVerification()) {
            return EvidenceType.VERIFICATION;
        } else {
            throw new UnknownEvidenceTypeException();
        }
    }

    public Gpg45Scores.Evidence getEvidenceScore() {
        return new Gpg45Scores.Evidence(getStrengthScore(), getValidityScore());
    }

    public boolean hasContraIndicators() {
        if (isIdentityFraud()) {
            return ci != null && !ci.isEmpty() && !(ci.size() == 1 && ci.get(0).equals(A01));
        }
        return ci != null && !ci.isEmpty();
    }

    private int numberOfContraIndicators() {
        return ci.size();
    }

    private boolean isActivity() {
        return activityScore != null
                && identityFraudScore == null
                && strengthScore == null
                && validityScore == null
                && verificationScore == null;
    }

    private boolean isIdentityFraud() {
        return identityFraudScore != null
                && activityScore == null
                && strengthScore == null
                && validityScore == null
                && verificationScore == null;
    }

    private boolean isEvidence() {
        return strengthScore != null
                && validityScore != null
                && activityScore == null
                && identityFraudScore == null
                && verificationScore == null;
    }

    private boolean isVerification() {
        return verificationScore != null
                && activityScore == null
                && identityFraudScore == null
                && strengthScore == null
                && validityScore == null;
    }

    @Getter
    public enum EvidenceType {
        ACTIVITY(
                generateComparator(CredentialEvidenceItem::getActivityScore),
                CredentialEvidenceItem::getActivityScore),
        IDENTITY_FRAUD(
                generateComparator(CredentialEvidenceItem::getIdentityFraudScore),
                CredentialEvidenceItem::getIdentityFraudScore),
        EVIDENCE(null, null),
        VERIFICATION(
                generateComparator(CredentialEvidenceItem::getVerificationScore),
                CredentialEvidenceItem::getVerificationScore);

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
}
