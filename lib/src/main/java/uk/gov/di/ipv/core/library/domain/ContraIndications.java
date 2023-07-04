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

    public Integer getContraIndicatorScores(
            final Map<String, ContraIndicatorScore> contraIndicatorScores) {
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
