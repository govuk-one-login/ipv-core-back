package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;

import java.util.Comparator;
import java.util.Map;
import java.util.Optional;

@Getter
@Builder(toBuilder = true)
public class ContraIndications {
    private final Map<String, ContraIndicator> contraIndicators;

    private Integer calculateDetectedScore(
            final Map<String, ContraIndicatorScore> contraIndicatorScores) {
        return contraIndicators.keySet().stream()
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScores.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    private Integer calculateCheckedScore(
            final Map<String, ContraIndicatorScore> contraIndicatorScoreMap) {
        return contraIndicators.values().stream()
                .filter(
                        contraIndicator ->
                                (contraIndicator.getMitigations() != null)
                                        && !contraIndicator.getMitigations().isEmpty())
                .map(
                        contraIndicator ->
                                contraIndicatorScoreMap
                                        .get(contraIndicator.getCode())
                                        .getCheckedScore())
                .reduce(0, Integer::sum);
    }

    public Integer getContraIndicatorScore(
            final Map<String, ContraIndicatorScore> contraIndicatorScoreMap,
            final boolean includeMitigation) {
        return calculateDetectedScore(contraIndicatorScoreMap)
                + (includeMitigation ? calculateCheckedScore(contraIndicatorScoreMap) : 0);
    }

    public Optional<ContraIndicator> getLatestContraIndicator() {
        return contraIndicators.values().stream()
                .max(Comparator.comparing(ContraIndicator::getIssuanceDate));
    }
}
