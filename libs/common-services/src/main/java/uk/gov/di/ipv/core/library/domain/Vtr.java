package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.P1_JOURNEYS_ENABLED;

public class Vtr {

    private final List<Vot> vots;

    public Vtr(List<String> rawVtr) {
        vots = rawVtr.stream().map(Vot::valueOf).toList();
    }

    public List<Vot> getRequestedVotsByStrengthDescending() {
        return Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH.stream().filter(vots::contains).toList();
    }

    // Refactor this out in PYIC-6984
    public Vot getLowestStrengthRequestedGpg45Vot(ConfigService configService) {
        var requestedGpg45VotsByStrengthDescending =
                getRequestedVotsByStrengthDescending().stream()
                        .filter(vot -> vot.getProfileType() == ProfileType.GPG45)
                        .toList();

        var lowestStrengthRequestedGpg45Vot =
                requestedGpg45VotsByStrengthDescending.get(
                        requestedGpg45VotsByStrengthDescending.size() - 1);

        if (lowestStrengthRequestedGpg45Vot == Vot.P1
                && !configService.enabled(P1_JOURNEYS_ENABLED)) {
            lowestStrengthRequestedGpg45Vot =
                    requestedGpg45VotsByStrengthDescending.get(
                            requestedGpg45VotsByStrengthDescending.size() - 2);
        }

        return lowestStrengthRequestedGpg45Vot;
    }

    // Refactor this out in PYIC-6984
    public Vot getLowestStrengthRequestedVot(ConfigService configService) {
        var requestedVotsByStrengthDescending = getRequestedVotsByStrengthDescending();

        var lowestStrengthRequestedVot =
                requestedVotsByStrengthDescending.get(requestedVotsByStrengthDescending.size() - 1);

        if (lowestStrengthRequestedVot == Vot.P1 && !configService.enabled(P1_JOURNEYS_ENABLED)) {
            lowestStrengthRequestedVot =
                    requestedVotsByStrengthDescending.get(
                            requestedVotsByStrengthDescending.size() - 2);
        }

        return lowestStrengthRequestedVot;
    }
}
