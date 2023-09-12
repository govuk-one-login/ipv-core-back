package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.oauth2.sdk.util.CollectionUtils;
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
import java.util.stream.Collectors;

@Getter
@Builder(toBuilder = true)
@ToString
public class ContraIndicators {
    private final Map<String, ContraIndicator> contraIndicatorsMap;

    private void validateContraIndicators(
            final Map<String, ContraIndicatorScore> contraIndicatorScores)
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
            final Map<String, ContraIndicatorScore> contraIndicatorScores) {
        return contraIndicatorsMap.keySet().stream()
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScores.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    private Integer calculateCheckedScore(
            final Map<String, ContraIndicatorScore> contraIndicatorScores,
            final Set<String> potentiallyMitigatedContraIndicators) {
        final Set<String> potentiallyAndActuallyMitigatedContraIndicators =
                contraIndicatorsMap.values().stream()
                        .filter(
                                contraIndicator ->
                                        !CollectionUtils.isEmpty(contraIndicator.getMitigation()))
                        .map(ContraIndicator::getCode)
                        .collect(Collectors.toSet());
        potentiallyAndActuallyMitigatedContraIndicators.addAll(
                potentiallyMitigatedContraIndicators);

        return potentiallyAndActuallyMitigatedContraIndicators.stream()
                .map(
                        contraIndicator ->
                                contraIndicatorScores.get(contraIndicator).getCheckedScore())
                .reduce(0, Integer::sum);
    }

    public Integer getContraIndicatorScore(
            final Map<String, ContraIndicatorScore> contraIndicatorScores,
            final boolean includeMitigation,
            final Set<String> inflightMitigations)
            throws UnrecognisedCiException {
        validateContraIndicators(contraIndicatorScores);
        return calculateDetectedScore(contraIndicatorScores)
                + (includeMitigation
                        ? calculateCheckedScore(contraIndicatorScores, inflightMitigations)
                        : 0);
    }

    public Optional<ContraIndicator> getLatestContraIndicator() {
        return contraIndicatorsMap.values().stream()
                .max(Comparator.comparing(ContraIndicator::getIssuanceDate));
    }
}
