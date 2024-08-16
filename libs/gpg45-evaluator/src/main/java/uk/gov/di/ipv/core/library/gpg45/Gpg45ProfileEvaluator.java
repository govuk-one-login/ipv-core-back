package uk.gov.di.ipv.core.library.gpg45;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.model.CheckDetails;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNullElse;
import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static software.amazon.awssdk.utils.StringUtils.isEmpty;
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
                                vc -> {
                                    IdentityCheckCredential credential =
                                            (IdentityCheckCredential) vc.getCredential();
                                    if (credential.getEvidence() != null) {
                                        return credential.getEvidence().stream();
                                    } else {
                                        return Stream.empty();
                                    }
                                })
                        .toList();

        return Gpg45Scores.builder()
                .withActivity(getMaxActivityScore(identityChecks))
                .withFraud(getMaxFraudScore(identityChecks))
                .withVerification(getMaxVerificationScore(identityChecks))
                .withEvidences(deduplicateEvidences(vcs))
                .build();
    }

    private List<Gpg45Scores.Evidence> deduplicateEvidences(List<VerifiableCredential> vcs) {
        var result = new ArrayList<Gpg45Scores.Evidence>();
        var deduplicatedEvidences = new HashMap<String, List<Gpg45Scores.Evidence>>();
        for (var vc : vcs) {
            if (vc.getCredential() instanceof IdentityCheckCredential idCheckVc) {
                var docType = getVcDocumentType(vc);
                var evidence =
                        getEvidences(
                                idCheckVc.getEvidence() != null
                                        ? idCheckVc.getEvidence()
                                        : Collections.emptyList());
                if (isEmpty(docType)) {
                    result.addAll(evidence);
                } else {
                    var existing = deduplicatedEvidences.get(docType);
                    if (isNullOrEmpty(existing) || evidence.get(0).compareTo(existing.get(0)) > 0) {
                        deduplicatedEvidences.put(docType, evidence);
                    }
                }
            }
        }
        result.addAll(deduplicatedEvidences.values().stream().flatMap(Collection::stream).toList());
        return result;
    }

    private String getVcDocumentType(VerifiableCredential vc) {
        if (vc.getCredential().getCredentialSubject() instanceof IdentityCheckSubject subject) {
            if (!isNullOrEmpty(subject.getDrivingPermit())) {
                return "drivingPermit";
            }
            if (!isNullOrEmpty(subject.getPassport())) {
                return "passport";
            }
            if (!isNullOrEmpty(subject.getBankAccount())) {
                return "bankAccount";
            }
            if (!isNullOrEmpty(subject.getResidencePermit())) {
                return "residencePermit";
            }
            if (!isNullOrEmpty(subject.getSocialSecurityRecord())) {
                return "socialSecurity";
            }
            if (!isNullOrEmpty(subject.getIdCard())) {
                return "idCard";
            }
        }
        return null;
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
        return identityChecks.stream()
                .mapToInt(Gpg45ProfileEvaluator::getVerificationScore)
                .max()
                .orElse(NO_SCORE);
    }

    public static int getVerificationScore(IdentityCheck identityCheck) {
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
                .sorted(Comparator.reverseOrder())
                .toList();
    }
}
