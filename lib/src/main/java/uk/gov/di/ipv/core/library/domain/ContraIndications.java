package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Builder(toBuilder = true)
@ToString
public class ContraIndications {
    private final Map<String, ContraIndicator> contraIndicators;

    private void validateContraIndicators(
            final Map<String, ContraIndicatorScore> contraIndicatorScores)
            throws UnrecognisedCiException {
        final Set<String> knownContraIndicators = contraIndicatorScores.keySet();
        final List<String> unknownContraIndicators =
                contraIndicators.keySet().stream()
                        .filter(ci -> !knownContraIndicators.contains(ci))
                        .collect(Collectors.toList());
        if (!unknownContraIndicators.isEmpty()) {
            throw new UnrecognisedCiException("Unrecognised CI code received from CIMIT");
        }
    }

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
            final boolean includeMitigation)
            throws UnrecognisedCiException {
        validateContraIndicators(contraIndicatorScores);
        return calculateDetectedScore(contraIndicatorScores)
                + (includeMitigation ? calculateCheckedScore(contraIndicatorScores) : 0);
    }

    public Optional<ContraIndicator> getLatestContraIndicator() {
        return contraIndicators.values().stream()
                .max(Comparator.comparing(ContraIndicator::getIssuanceDate));
    }
}
