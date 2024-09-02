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
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;

public class CimitUtilityService {
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private final ConfigService configService;

    public CimitUtilityService(ConfigService configService) {
        this.configService = configService;
    }

    public boolean isBreachingCiThreshold(
            ContraIndicators contraIndicators, Vot confidenceRequested) {
        return isScoreBreachingCiThreshold(
                contraIndicators.getContraIndicatorScore(
                        configService.getContraIndicatorConfigMap()),
                confidenceRequested);
    }

    public boolean isBreachingCiThresholdIfMitigated(
            ContraIndicator ci, ContraIndicators cis, Vot confidenceRequested) {
        var scoreOnceMitigated =
                cis.getContraIndicatorScore(configService.getContraIndicatorConfigMap())
                        + configService
                                .getContraIndicatorConfigMap()
                                .get(ci.getCode())
                                .getCheckedScore();
        return isScoreBreachingCiThreshold(scoreOnceMitigated, confidenceRequested);
    }

    private boolean isScoreBreachingCiThreshold(int score, Vot vot) {
        return score
                > Integer.parseInt(configService.getParameter(CI_SCORING_THRESHOLD, vot.name()));
    }

    public Optional<JourneyResponse> getMitigationJourneyIfBreaching(
            ContraIndicators cis, Vot confidenceRequested) throws ConfigException {
        if (isBreachingCiThreshold(cis, confidenceRequested)) {
            return Optional.of(
                    getCiMitigationJourneyResponse(cis, confidenceRequested)
                            .orElse(JOURNEY_FAIL_WITH_CI));
        }
        return Optional.empty();
    }

    private Optional<JourneyResponse> getCiMitigationJourneyResponse(
            ContraIndicators contraIndicators, Vot confidenceRequested) throws ConfigException {
        // Try to mitigate an unmitigated ci to resolve the threshold breach
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators.getUsersContraIndicators()) {
            if (isCiMitigatable(ci)
                    && !isBreachingCiThresholdIfMitigated(
                            ci, contraIndicators, confidenceRequested)) {
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
