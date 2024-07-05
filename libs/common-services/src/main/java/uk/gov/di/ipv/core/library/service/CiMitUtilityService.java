package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.P1_JOURNEYS_ENABLED;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;

public class CiMitUtilityService {
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private final ConfigService configService;

    public CiMitUtilityService(ConfigService configService) {
        this.configService = configService;
    }

    public boolean isBreachingCiThreshold(ContraIndicators contraIndicators, List<String> vtr) {
        return isScoreBreachingCiThreshold(
                contraIndicators.getContraIndicatorScore(
                        configService.getContraIndicatorConfigMap()),
                vtr);
    }

    public boolean isBreachingCiThresholdIfMitigated(
            ContraIndicator ci, ContraIndicators cis, List<String> vtr) {
        var scoreOnceMitigated =
                cis.getContraIndicatorScore(configService.getContraIndicatorConfigMap())
                        + configService
                                .getContraIndicatorConfigMap()
                                .get(ci.getCode())
                                .getCheckedScore();
        return isScoreBreachingCiThreshold(scoreOnceMitigated, vtr);
    }

    private boolean isScoreBreachingCiThreshold(int score, List<String> vtr) {
        // Refactor this out in PYIC-6984
        var newIdentityLevel = Vot.P2;
        if (configService.enabled(P1_JOURNEYS_ENABLED) && vtr.contains(Vot.P1.name())) {
            newIdentityLevel = Vot.P1;
        }

        return score
                > Integer.parseInt(
                        configService.getSsmParameter(
                                CI_SCORING_THRESHOLD, newIdentityLevel.name()));
    }

    public Optional<JourneyResponse> checkCiLevel(ContraIndicators cis, List<String> vtr)
            throws ConfigException {
        if (isBreachingCiThreshold(cis, vtr)) {
            return Optional.of(
                    getCiMitigationJourneyResponse(cis, vtr).orElse(JOURNEY_FAIL_WITH_CI));
        }
        return Optional.empty();
    }

    public Optional<JourneyResponse> getCiMitigationJourneyResponse(
            ContraIndicators contraIndicators, List<String> vtr) throws ConfigException {
        // Try to mitigate an unmitigated ci to resolve the threshold breach
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators.getUsersContraIndicators()) {
            if (isCiMitigatable(ci)
                    && !isBreachingCiThresholdIfMitigated(ci, contraIndicators, vtr)) {
                // Prevent new mitigation journey if there is already a mitigated CI that fixes the
                // breach
                if (hasMitigatedContraIndicator(contraIndicators).isPresent()) {
                    return Optional.empty();
                }
                return getMitigationJourneyResponse(
                        cimitConfig.get(ci.getCode()), ci.getDocument());
            }
        }
        return Optional.empty();
    }

    public Optional<JourneyResponse> getMitigatedCiJourneyResponse(ContraIndicator ci)
            throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        if (cimitConfig.containsKey(ci.getCode()) && ci.isMitigated()) {
            return getMitigationJourneyResponse(cimitConfig.get(ci.getCode()), ci.getDocument());
        }
        return Optional.empty();
    }

    public Optional<ContraIndicator> hasMitigatedContraIndicator(
            ContraIndicators contraIndicators) {
        return contraIndicators.getUsersContraIndicators().stream()
                .filter(ContraIndicator::isMitigated)
                .findFirst();
    }

    private Optional<JourneyResponse> getMitigationJourneyResponse(
            List<MitigationRoute> mitigationRoute, String document) {
        String documentType = document != null ? document.split("/")[0] : null;
        return mitigationRoute.stream()
                .filter(mr -> (mr.document() == null || mr.document().equals(documentType)))
                .findFirst()
                .map(MitigationRoute::event)
                .map(JourneyResponse::new);
    }

    private boolean isCiMitigatable(ContraIndicator ci) throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        return cimitConfig.containsKey(ci.getCode()) && !ci.isMitigated();
    }
}
