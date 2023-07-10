package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.Comparator;
import java.util.Map;
import java.util.Optional;

@Getter
@Builder(toBuilder = true)
@ToString
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
            final Map<String, ContraIndicatorScore> contraIndicatorScores) {
        return contraIndicators.values().stream()
                .filter(
                        contraIndicator ->
                                !CollectionUtils.isEmpty(contraIndicator.getMitigations()))
                .map(
                        contraIndicator ->
                                contraIndicatorScores
                                        .get(contraIndicator.getCode())
                                        .getCheckedScore())
                .reduce(0, Integer::sum);
    }

    public Integer getContraIndicatorScore(
            final Map<String, ContraIndicatorScore> contraIndicatorScores,
            final boolean includeMitigation) {
        return calculateDetectedScore(contraIndicatorScores)
                + (includeMitigation ? calculateCheckedScore(contraIndicatorScores) : 0);
    }

    public Optional<ContraIndicator> getLatestContraIndicator() {
        return contraIndicators.values().stream()
                .max(Comparator.comparing(ContraIndicator::getIssuanceDate));
    }
}
