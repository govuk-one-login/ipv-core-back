package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Getter
@Builder(toBuilder = true)
@ToString
public class ContraIndicators {
    private final Map<String, ContraIndicator> contraIndicatorsMap;

    public Integer getContraIndicatorScore(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores)
            throws UnrecognisedCiException {
        validateContraIndicators(contraIndicatorScores);
        return calculateDetectedScore(contraIndicatorScores)
                + calculateCheckedScore(contraIndicatorScores);
    }

    public Optional<ContraIndicator> getLatestContraIndicator() {
        return contraIndicatorsMap.values().stream()
                .max(Comparator.comparing(ContraIndicator::getIssuanceDate));
    }

    public boolean hasMitigations() {
        return contraIndicatorsMap.values().stream().anyMatch(ContraIndicator::isMitigated);
    }

    private void validateContraIndicators(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores)
            throws UnrecognisedCiException {
        final Set<String> knownContraIndicators = contraIndicatorScores.keySet();
        final List<String> unknownContraIndicators =
                contraIndicatorsMap.keySet().stream()
                        .filter(ci -> !knownContraIndicators.contains(ci))
                        .toList();
        if (!unknownContraIndicators.isEmpty()) {
            throw new UnrecognisedCiException("Unrecognised CI code received from CIMIT");
        }
    }

    private Integer calculateDetectedScore(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return contraIndicatorsMap.keySet().stream()
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScores.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    private Integer calculateCheckedScore(
            final Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return contraIndicatorsMap.values().stream()
                .filter(ContraIndicator::isMitigated)
                .map(
                        contraIndicator ->
                                contraIndicatorScores
                                        .get(contraIndicator.getCode())
                                        .getCheckedScore())
                .reduce(0, Integer::sum);
    }
}
