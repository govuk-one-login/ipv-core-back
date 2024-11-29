package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;

public class CimitUtilityService {
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private final ConfigService configService;

    public CimitUtilityService(ConfigService configService) {
        this.configService = configService;
    }

    public int getContraIndicatorScore(List<ContraIndicator> contraIndicators)
            throws UnrecognisedCiException {
        var scores = configService.getContraIndicatorConfigMap();
        validateContraIndicators(contraIndicators, scores);
        return calculateDetectedScore(contraIndicators, scores)
                + calculateCheckedScore(contraIndicators, scores);
    }

    private void validateContraIndicators(
            List<ContraIndicator> contraIndicators,
            Map<String, ContraIndicatorConfig> contraIndicatorScores)
            throws UnrecognisedCiException {
        final Set<String> knownContraIndicators = contraIndicatorScores.keySet();
        final List<String> unknownContraIndicators =
                contraIndicators.stream()
                        .map(ContraIndicator::getCode)
                        .filter(ci -> !knownContraIndicators.contains(ci))
                        .toList();
        if (!unknownContraIndicators.isEmpty()) {
            throw new UnrecognisedCiException("Unrecognised CI code received from CIMIT");
        }
    }

    private int calculateDetectedScore(
            List<ContraIndicator> contraIndicators,
            Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return contraIndicators.stream()
                .map(ContraIndicator::getCode)
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScores.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    private int calculateCheckedScore(
            List<ContraIndicator> contraIndicators,
            Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return contraIndicators.stream()
                .filter(this::isMitigated)
                .map(
                        contraIndicator ->
                                contraIndicatorScores
                                        .get(contraIndicator.getCode())
                                        .getCheckedScore())
                .reduce(0, Integer::sum);
    }

    public boolean isBreachingCiThreshold(
            List<ContraIndicator> contraIndicators, Vot confidenceRequested) {
        return isScoreBreachingCiThreshold(
                getContraIndicatorScore(contraIndicators), confidenceRequested);
    }

    public boolean isBreachingCiThresholdIfMitigated(
            ContraIndicator ci, List<ContraIndicator> cis, Vot confidenceRequested) {
        var scoreOnceMitigated =
                getContraIndicatorScore(cis)
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
            List<ContraIndicator> cis, Vot confidenceRequested) throws ConfigException {
        if (isBreachingCiThreshold(cis, confidenceRequested)) {
            return Optional.of(
                    getCiMitigationJourneyResponse(cis, confidenceRequested)
                            .orElse(JOURNEY_FAIL_WITH_CI));
        }
        return Optional.empty();
    }

    private Optional<JourneyResponse> getCiMitigationJourneyResponse(
            List<ContraIndicator> contraIndicators, Vot confidenceRequested)
            throws ConfigException {
        // Try to mitigate an unmitigated ci to resolve the threshold breach
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators) {
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
        if (cimitConfig.containsKey(ci.getCode()) && isMitigated(ci)) {
            return getMitigationJourneyResponse(cimitConfig.get(ci.getCode()), ci.getDocument());
        }
        return Optional.empty();
    }

    public Optional<ContraIndicator> hasMitigatedContraIndicator(
            List<ContraIndicator> contraIndicators) {
        return contraIndicators.stream().filter(this::isMitigated).findFirst();
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

    private boolean isMitigated(ContraIndicator ci) {
        return ci.getMitigation() != null && !ci.getMitigation().isEmpty();
    }

    private boolean isCiMitigatable(ContraIndicator ci) throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        return cimitConfig.containsKey(ci.getCode()) && !isMitigated(ci);
    }
}
