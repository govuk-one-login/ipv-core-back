package uk.gov.di.ipv.core.library.useridentity.service;

import lombok.AllArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.ContraIndicator;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

@AllArgsConstructor
public class VotMatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    private final UserIdentityService userIdentityService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final CimitUtilityService cimitUtilityService;

    // Find the strongest matching vot from those requested, and also find the strongest vot that is
    // met.
    public VotMatchingResult findStrongestMatches(
            List<Vot> requestedVots,
            List<VerifiableCredential> vcs,
            List<ContraIndicator> contraIndicators,
            boolean areGpg45VcsCorrelated)
            throws ParseException {

        Optional<VotMatchingResult.VotAndProfile> strongestMatchedVot = Optional.empty();
        Optional<VotMatchingResult.VotAndProfile> strongestRequestedMatchedVot = Optional.empty();

        var operationalVcs = VcHelper.filterVCBasedOnProfileType(vcs, OPERATIONAL_HMRC);
        var gpg45Vcs = VcHelper.filterVCBasedOnProfileType(vcs, GPG45);
        var gpg45Scores = gpg45ProfileEvaluator.buildScore(gpg45Vcs);

        for (Vot vot : SUPPORTED_VOTS_BY_DESCENDING_STRENGTH) {
            var potentialMatch =
                    checkMatch(
                            vot,
                            gpg45Scores,
                            operationalVcs,
                            gpg45Vcs,
                            contraIndicators,
                            areGpg45VcsCorrelated);

            if (potentialMatch.isPresent()) {
                if (strongestMatchedVot.isEmpty()) {
                    strongestMatchedVot = potentialMatch;
                }
                if (requestedVots.contains(vot)) {
                    strongestRequestedMatchedVot = potentialMatch;
                }
            }

            if (strongestMatchedVot.isPresent() && strongestRequestedMatchedVot.isPresent()) {
                break;
            }
        }

        return new VotMatchingResult(
                strongestMatchedVot, strongestRequestedMatchedVot, gpg45Scores);
    }

    private Optional<VotMatchingResult.VotAndProfile> checkMatch(
            Vot vot,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> operationalVcs,
            List<VerifiableCredential> gpg45Vcs,
            List<ContraIndicator> contraIndicators,
            boolean areGpg45VcsCorrelated)
            throws ParseException {

        if (vot.getProfileType().equals(GPG45) && areGpg45VcsCorrelated) {
            var matchedGpg45Profile =
                    achievedWithGpg45Profile(vot, gpg45Vcs, gpg45Scores, contraIndicators);

            if (matchedGpg45Profile.isPresent()) {
                return Optional.of(new VotMatchingResult.VotAndProfile(vot, matchedGpg45Profile));
            }
        } else if (vot.getProfileType() == OPERATIONAL_HMRC
                && hasOperationalProfileVc(vot, operationalVcs, contraIndicators)) {
            return Optional.of(new VotMatchingResult.VotAndProfile(vot, Optional.empty()));
        }

        return Optional.empty();
    }

    private Optional<Gpg45Profile> achievedWithGpg45Profile(
            Vot requestedVot,
            List<VerifiableCredential> gpg45Vcs,
            Gpg45Scores gpg45Scores,
            List<ContraIndicator> contraIndicators) {

        var isFraudScoreRequired = !VcHelper.hasUnavailableOrNotApplicableFraudCheck(gpg45Vcs);
        var achievableProfiles = requestedVot.getSupportedGpg45Profiles(isFraudScoreRequired);

        Optional<Gpg45Profile> matchedGpg45Profile =
                !userIdentityService.checkRequiresAdditionalEvidence(gpg45Vcs)
                        ? gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, achievableProfiles)
                        : Optional.empty();

        if (matchedGpg45Profile.isEmpty() || isBreaching(contraIndicators, requestedVot)) {
            return Optional.empty();
        }

        // Successful match
        LOGGER.info(
                LogHelper.buildLogMessage("GPG45 profile has been met.")
                        .with(LOG_VOT.getFieldName(), requestedVot)
                        .with(
                                LOG_GPG45_PROFILE.getFieldName(),
                                matchedGpg45Profile.get().getLabel()));
        return matchedGpg45Profile;
    }

    private boolean hasOperationalProfileVc(
            Vot requestedVot,
            List<VerifiableCredential> vcs,
            List<ContraIndicator> contraIndicators)
            throws ParseException {
        for (var vc : vcs) {
            var vcContainsVot =
                    requestedVot.name().equals(vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME));

            if (!vcContainsVot || isBreaching(contraIndicators, requestedVot)) {
                continue;
            }

            // Successful match
            LOGGER.info(
                    LogHelper.buildLogMessage("Operational profile matched")
                            .with(LOG_VOT.getFieldName(), requestedVot));
            return true;
        }
        return false;
    }

    private boolean isBreaching(List<ContraIndicator> contraIndicators, Vot vot) {
        return !contraIndicators.isEmpty()
                && cimitUtilityService.isBreachingCiThreshold(contraIndicators, vot);
    }
}
