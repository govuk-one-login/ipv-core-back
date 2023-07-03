package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;

import java.util.*;

@Getter
@Builder(toBuilder = true)
public class ContraIndications {
    private final Map<String, ContraIndicator> contraIndicators;

    private final Map<String, ContraIndicatorScore> contraIndicatorScores;

    public Integer getContraIndicatorScores() {
        return contraIndicators.keySet().stream()
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScores.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    public Optional<ContraIndicator> getLatestContraIndicator() {
        return contraIndicators.values().stream()
                .max(Comparator.comparing(ContraIndicator::getIssuanceDate));
    }
}
