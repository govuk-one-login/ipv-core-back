package uk.gov.di.ipv.core.library.service;

import lombok.AllArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.ContraIndicator;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

@AllArgsConstructor
public class VotMatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    private final UserIdentityService userIdentityService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final CimitUtilityService cimitUtilityService;

    public VotMatcher(
            UserIdentityService userIdentityService, Gpg45ProfileEvaluator gpg45ProfileEvaluator) {
        this(userIdentityService, gpg45ProfileEvaluator, null);
    }

    public Optional<VotMatchingResult> matchFirstVot(
            List<Vot> vots,
            List<VerifiableCredential> vcs,
            List<ContraIndicator> contraIndicators,
            boolean areGpg45VcsCorrelated)
            throws ParseException {

        var gpg45Vcs = VcHelper.filterVCBasedOnProfileType(vcs, GPG45);
        var gpg45Scores = gpg45ProfileEvaluator.buildScore(gpg45Vcs);
        var operationalVcs = VcHelper.filterVCBasedOnProfileType(vcs, OPERATIONAL_HMRC);

        for (Vot vot : vots) {
            if (vot.getProfileType().equals(GPG45) && areGpg45VcsCorrelated) {
                var matchedGpg45Profile =
                        achievedWithGpg45Profile(vot, gpg45Vcs, gpg45Scores, contraIndicators);
                if (matchedGpg45Profile.isPresent()) {
                    return Optional.of(
                            new VotMatchingResult(vot, matchedGpg45Profile.get(), gpg45Scores));
                }
            } else if (hasOperationalProfileVc(vot, operationalVcs, contraIndicators)) {
                return Optional.of(new VotMatchingResult(vot, null, null));
            }
        }
        return Optional.empty();
    }

    private Optional<Gpg45Profile> achievedWithGpg45Profile(
            Vot requestedVot,
            List<VerifiableCredential> gpg45Vcs,
            Gpg45Scores gpg45Scores,
            List<ContraIndicator> contraIndicators) {

        var achievableProfiles = requestedVot.getSupportedGpg45Profiles();
        if (requestedVot == Vot.P2 && userIdentityService.isFraudCheckUnavailable(gpg45Vcs)) {
            achievableProfiles = new ArrayList<>(achievableProfiles);
            achievableProfiles.add(Gpg45Profile.M1C);
        }

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
