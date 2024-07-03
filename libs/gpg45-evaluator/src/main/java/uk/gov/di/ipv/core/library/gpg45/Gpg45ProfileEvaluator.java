package uk.gov.di.ipv.core.library.gpg45;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.model.CheckDetails;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNullElse;
import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class Gpg45ProfileEvaluator {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final int NO_SCORE = 0;

    public Optional<Gpg45Profile> getFirstMatchingProfile(
            Gpg45Scores gpg45Scores, List<Gpg45Profile> profiles) {
        return profiles.stream()
                .filter(
                        profile -> {
                            boolean profileMet = profile.isSatisfiedBy(gpg45Scores);
                            if (profileMet) {
                                var message =
                                        new StringMapMessage()
                                                .with(
                                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                                        "GPG45 profile has been met.")
                                                .with(
                                                        LOG_GPG45_PROFILE.getFieldName(),
                                                        profile.getLabel());
                                LOGGER.info(message);
                            }
                            return profileMet;
                        })
                .findFirst();
    }

    public Gpg45Scores buildScore(List<VerifiableCredential> vcs) {

        var identityChecks =
                vcs.stream()
                        .filter(vc -> vc.getCredential() instanceof IdentityCheckCredential)
                        .flatMap(
                                vc ->
                                        ((IdentityCheckCredential) vc.getCredential())
                                                .getEvidence().stream())
                        .toList();

        return Gpg45Scores.builder()
                .withActivity(getMaxActivityScore(identityChecks))
                .withFraud(getMaxFraudScore(identityChecks))
                .withVerification(getMaxVerificationScore(identityChecks))
                .withEvidences(getEvidences(identityChecks))
                .build();
    }

    private int getMaxActivityScore(List<IdentityCheck> identityChecks) {
        return identityChecks.stream()
                .mapToInt(check -> requireNonNullElse(check.getActivityHistoryScore(), NO_SCORE))
                .max()
                .orElse(NO_SCORE);
    }

    private int getMaxFraudScore(List<IdentityCheck> identityChecks) {
        return identityChecks.stream()
                .mapToInt(check -> requireNonNullElse(check.getIdentityFraudScore(), NO_SCORE))
                .max()
                .orElse(NO_SCORE);
    }

    private int getMaxVerificationScore(List<IdentityCheck> identityChecks) {
        return identityChecks.stream().mapToInt(this::getVerificationScore).max().orElse(NO_SCORE);
    }

    private int getVerificationScore(IdentityCheck identityCheck) {
        if (identityCheck.getVerificationScore() != null) {
            return identityCheck.getVerificationScore();
        }
        if (!isNullOrEmpty(identityCheck.getCheckDetails())) {
            return identityCheck.getCheckDetails().stream()
                    .filter(
                            checkMethod ->
                                    checkMethod.getBiometricVerificationProcessLevel() != null)
                    .findFirst()
                    .map(CheckDetails::getBiometricVerificationProcessLevel)
                    .orElse(NO_SCORE);
        }
        return NO_SCORE;
    }

    private List<Gpg45Scores.Evidence> getEvidences(List<IdentityCheck> identityChecks) {
        return identityChecks.stream()
                .flatMap(
                        identityCheck -> {
                            if (identityCheck.getStrengthScore() != null
                                    && identityCheck.getValidityScore() != null) {
                                return Stream.of(
                                        new Gpg45Scores.Evidence(
                                                identityCheck.getStrengthScore(),
                                                identityCheck.getValidityScore()));
                            }
                            return Stream.empty();
                        })
                .toList();
    }
}
