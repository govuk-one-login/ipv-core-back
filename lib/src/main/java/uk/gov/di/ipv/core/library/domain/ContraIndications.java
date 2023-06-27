package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Getter
@Builder
public class ContraIndications {
    private final Map<String, ContraIndicator> contraIndicatorMap;

    private Integer getContraIndicatorDetectedScore(
            Map<String, ContraIndicatorScore> contraIndicatorScoreMap) {
        return contraIndicatorMap.keySet().stream()
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScoreMap.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    private Integer getContraIndicatorCheckedScore(
            Map<String, ContraIndicatorScore> contraIndicatorScoreMap) {
        return contraIndicatorMap.values().stream()
                .filter(
                        contraIndicator ->
                                (contraIndicator.getMitigations() != null)
                                        && !contraIndicator.getMitigations().isEmpty())
                .map(
                        contraIndicator ->
                                contraIndicatorScoreMap
                                        .get(contraIndicator.getContraIndicatorCode())
                                        .getCheckedScore())
                .reduce(0, Integer::sum);
    }

    public Integer getContraIndicatorScore(
            Map<String, ContraIndicatorScore> contraIndicatorScoreMap, boolean includeMitigation) {
        return getContraIndicatorDetectedScore(contraIndicatorScoreMap)
                + (includeMitigation ? getContraIndicatorCheckedScore(contraIndicatorScoreMap) : 0);
    }

    public Optional<ContraIndicator> getLatestContraIndicator() {
        if (contraIndicatorMap.isEmpty()) {
            return Optional.empty();
        }
        final List<ContraIndicator> contraIndicators = new ArrayList<>(contraIndicatorMap.values());
        Collections.sort(contraIndicators);
        return Optional.of(contraIndicators.get(contraIndicators.size() - 1));
    }
}
