package uk.gov.di.ipv.core.library.gpg45;

import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Gpg45Scores is a collection of values that represent the scores gathered when assessing identity
 * proofing using GPG 45.
 *
 * <p>Objects if this class are immutable.
 */
public class Gpg45Scores {

    public static final Evidence EV_00 = new Gpg45Scores.Evidence(0, 0);
    public static final Evidence EV_11 = new Gpg45Scores.Evidence(1, 1);
    public static final Evidence EV_22 = new Gpg45Scores.Evidence(2, 2);
    public static final Evidence EV_32 = new Gpg45Scores.Evidence(3, 2);
    public static final Evidence EV_33 = new Gpg45Scores.Evidence(3, 3);
    public static final Evidence EV_40 = new Gpg45Scores.Evidence(4, 0);
    public static final Evidence EV_42 = new Gpg45Scores.Evidence(4, 2);
    public static final Evidence EV_43 = new Gpg45Scores.Evidence(4, 3);
    public static final Evidence EV_44 = new Gpg45Scores.Evidence(4, 4);

    private final List<Evidence> evidences;
    private final int activity;
    private final int fraud;
    private final int verification;

    public Gpg45Scores(int strength, int validity, int activity, int fraud, int verification) {
        this.activity = activity;
        this.fraud = fraud;
        this.verification = verification;
        this.evidences = List.of(new Evidence(strength, validity));
    }

    public Gpg45Scores(Evidence evidence, int activity, int fraud, int verification) {
        this.activity = activity;
        this.fraud = fraud;
        this.verification = verification;
        this.evidences = List.of(evidence);
    }

    public Gpg45Scores(
            Evidence evidence1, Evidence evidence2, int activity, int fraud, int verification) {
        this(Arrays.asList(evidence1, evidence2), activity, fraud, verification);
    }

    public Gpg45Scores(
            Evidence evidence1,
            Evidence evidence2,
            Evidence evidence3,
            int activity,
            int fraud,
            int verification) {
        this(Arrays.asList(evidence1, evidence2, evidence3), activity, fraud, verification);
    }

    public Gpg45Scores(List<Evidence> evidence, int activity, int fraud, int verification) {
        this.activity = activity;
        this.fraud = fraud;
        this.verification = verification;
        this.evidences =
                evidence.stream()
                        .sorted(
                                Comparator.comparing(Evidence::getStrength)
                                        .thenComparing(Evidence::getValidity)
                                        .reversed())
                        .toList();
    }

    public int getActivity() {
        return activity;
    }

    public int getFraud() {
        return fraud;
    }

    public int getVerification() {
        return verification;
    }

    public List<Evidence> getEvidences() {
        return evidences;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        return "[" + evidences + ", " + activity + ", " + fraud + ", " + verification + "]";
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (other == null || getClass() != other.getClass()) return false;
        Gpg45Scores that = (Gpg45Scores) other;
        return activity == that.activity
                && fraud == that.fraud
                && verification == that.verification
                && evidences.equals(that.evidences);
    }

    private Gpg45Scores difference(Gpg45Scores other) {
        return new Gpg45Scores(
                diffEvidence(other),
                other.getActivity() - activity,
                other.getFraud() - fraud,
                other.getVerification() - verification);
    }

    private List<Gpg45Scores.Evidence> diffEvidence(Gpg45Scores target) {

        var thisEvidenceSize = evidences.size();
        var targetEvidenceSize = target.evidences.size();

        if (thisEvidenceSize > 1 || targetEvidenceSize > 1) {
            throw new IllegalArgumentException(
                    "It's currently unclear how to define the difference between multiple pieces of evidence.");
        }

        var thisEvidence =
                thisEvidenceSize == 0 ? new Gpg45Scores.Evidence(0, 0) : evidences.get(0);
        var targetEvidence =
                targetEvidenceSize == 0 ? new Gpg45Scores.Evidence(0, 0) : target.evidences.get(0);

        return List.of(
                new Gpg45Scores.Evidence(
                        targetEvidence.getStrength() - thisEvidence.getStrength(),
                        targetEvidence.getValidity() - thisEvidence.getValidity()));
    }

    public Gpg45Scores calculateRequiredScores(Gpg45Profile target) {
        Gpg45Scores targetScores = target.getScores();
        Gpg45Scores diff = difference(targetScores);
        return new Gpg45Scores(
                calculateRequiredEvidences(diff.getEvidences(), targetScores.getEvidences()),
                diff.getActivity() > 0 ? targetScores.getActivity() : 0,
                diff.getFraud() > 0 ? targetScores.getFraud() : 0,
                diff.getVerification() > 0 ? targetScores.getVerification() : 0);
    }

    private List<Gpg45Scores.Evidence> calculateRequiredEvidences(
            List<Gpg45Scores.Evidence> diffEvidences, List<Gpg45Scores.Evidence> targetEvidences) {

        var diffEvidenceSize = diffEvidences.size();
        var targetEvidenceSize = targetEvidences.size();

        if (diffEvidenceSize > 1 || targetEvidenceSize > 1) {
            throw new IllegalArgumentException(
                    "It's currently unclear how to define the required evidence for multiple pieces of evidence.");
        }

        var requiredEvidences = new ArrayList<Evidence>();
        var maxEvidence = Math.max(diffEvidenceSize, targetEvidenceSize);
        for (int i = 0; i < maxEvidence; i++) {
            var diff = diffEvidences.get(i);
            if (diff.getStrength() > 0 || diff.getValidity() > 0) {
                requiredEvidences.add(targetEvidences.get(i));
            } else {
                requiredEvidences.add(EV_00);
            }
        }
        return requiredEvidences;
    }

    @Override
    public int hashCode() {
        return Objects.hash(evidences, activity, fraud, verification);
    }

    static class Builder {

        private List<Evidence> evidences = new ArrayList<>();
        private int activity;
        private int fraud;
        private int verification;

        public Builder withEvidence(Evidence evidence) {
            this.evidences.add(evidence);
            return this;
        }

        public Builder withEvidences(List<Evidence> evidencesList) {
            this.evidences =
                    Stream.concat(this.evidences.stream(), evidencesList.stream())
                            .collect(Collectors.toList());
            return this;
        }

        public Builder withActivity(int activity) {
            this.activity = activity;
            return this;
        }

        public Builder withFraud(int fraud) {
            this.fraud = fraud;
            return this;
        }

        public Builder withVerification(int verification) {
            this.verification = verification;
            return this;
        }

        public Gpg45Scores build() {
            return new Gpg45Scores(evidences, activity, fraud, verification);
        }
    }

    public static class Evidence {
        private final int strength;
        private final int validity;

        public Evidence(int strength, int validity) {
            this.strength = strength;
            this.validity = validity;
        }

        public int getValidity() {
            return validity;
        }

        public int getStrength() {
            return strength;
        }

        @Override
        public String toString() {
            return "" + strength + validity;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Evidence evidence = (Evidence) o;
            return strength == evidence.strength && validity == evidence.validity;
        }

        @Override
        public int hashCode() {
            return Objects.hash(strength, validity);
        }
    }
}
