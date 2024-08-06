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
        var deduplicatedVcs = deduplicateVcsByDocumentType(vcs);
        var identityChecks =
                deduplicatedVcs.stream()
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

    private List<VerifiableCredential> deduplicateVcsByDocumentType(
            List<VerifiableCredential> vcs) {
        var result = new ArrayList<VerifiableCredential>();
        var deduplicatedVcs = new HashMap<String, VerifiableCredential>();
        for (var vc : vcs) {
            var docType = getVcDocumentType(vc);
            if (isEmpty(docType)) {
                result.add(vc);
            } else {
                var existing = deduplicatedVcs.get(docType);
                deduplicatedVcs.putIfAbsent(
                        docType, selectVerifiableCredentialWithSameDocumentType(existing, vc));
            }
        }
        result.addAll(deduplicatedVcs.values());
        return result;
    }

    private VerifiableCredential selectVerifiableCredentialWithSameDocumentType(
            VerifiableCredential vc1, VerifiableCredential vc2) {
        if (vc1 == null) {
            return vc2;
        }
        if (vc2 == null) {
            return vc1;
        }
        if (vc1.getCredential() instanceof IdentityCheckCredential idCheck1
                && vc2.getCredential() instanceof IdentityCheckCredential idCheck2) {
            var maxStrength1 =
                    idCheck1.getEvidence().stream()
                            .mapToInt(IdentityCheck::getStrengthScore)
                            .max()
                            .orElse(NO_SCORE);
            var maxStrength2 =
                    idCheck2.getEvidence().stream()
                            .mapToInt(IdentityCheck::getStrengthScore)
                            .max()
                            .orElse(NO_SCORE);
            if (maxStrength1 > maxStrength2) {
                return vc1;
            } else if (maxStrength2 > maxStrength1) {
                return vc2;
            } else {
                var maxValidity1 =
                        idCheck1.getEvidence().stream()
                                .mapToInt(IdentityCheck::getValidityScore)
                                .max()
                                .orElse(NO_SCORE);
                var maxValidity2 =
                        idCheck2.getEvidence().stream()
                                .mapToInt(IdentityCheck::getValidityScore)
                                .max()
                                .orElse(NO_SCORE);
                if (maxValidity1 > maxValidity2) {
                    return vc1;
                } else if (maxValidity2 > maxValidity1) {
                    return vc2;
                }
            }
        }
        return vc1;
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
                .toList();
    }
}
