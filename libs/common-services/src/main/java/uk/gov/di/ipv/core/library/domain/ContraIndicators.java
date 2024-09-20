package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Map;
import java.util.Set;

public record ContraIndicators(List<ContraIndicator> usersContraIndicators) {
    public Integer getContraIndicatorScore(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores)
            throws UnrecognisedCiException {
        validateContraIndicators(contraIndicatorScores);
        return calculateDetectedScore(contraIndicatorScores)
                + calculateCheckedScore(contraIndicatorScores);
    }

    public boolean hasMitigations() {
        return usersContraIndicators.stream().anyMatch(this::isMitigated);
    }

    private void validateContraIndicators(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores)
            throws UnrecognisedCiException {
        final Set<String> knownContraIndicators = contraIndicatorScores.keySet();
        final List<String> unknownContraIndicators =
                usersContraIndicators.stream()
                        .map(ContraIndicator::getCode)
                        .filter(ci -> !knownContraIndicators.contains(ci))
                        .toList();
        if (!unknownContraIndicators.isEmpty()) {
            throw new UnrecognisedCiException("Unrecognised CI code received from CIMIT");
        }
    }

    private Integer calculateDetectedScore(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return usersContraIndicators.stream()
                .map(ContraIndicator::getCode)
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScores.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    private Integer calculateCheckedScore(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return usersContraIndicators.stream()
                .filter(this::isMitigated)
                .map(
                        contraIndicator ->
                                contraIndicatorScores
                                        .get(contraIndicator.getCode())
                                        .getCheckedScore())
                .reduce(0, Integer::sum);
    }

    private boolean isMitigated(ContraIndicator ci) {
        return ci.getMitigation() != null && !ci.getMitigation().isEmpty();
    }
}
