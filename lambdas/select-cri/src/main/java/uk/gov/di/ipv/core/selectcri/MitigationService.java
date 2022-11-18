package uk.gov.di.ipv.core.selectcri;

import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class MitigationService {

    private final ConfigurationService configurationService;

    public MitigationService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public boolean isMitigationPossible(
            List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetails) {

        List<ContraIndicatorMitigationDetailsDto> mitigationPossibleItems =
                contraIndicatorMitigationDetails.stream()
                        .filter(this::canBeMitigated)
                        .collect(Collectors.toList());
        return !mitigationPossibleItems.isEmpty();
    }

    private boolean canBeMitigated(
            ContraIndicatorMitigationDetailsDto contraIndicatorMitigationDetailsDto) {
        Map<String, ContraIndicatorScore> contraIndicatorScoresMap =
                configurationService.getContraIndicatorScoresMap();
        ContraIndicatorScore scoresConfig =
                contraIndicatorScoresMap.get(contraIndicatorMitigationDetailsDto.getCi());
        return scoresConfig.getCi().equals(contraIndicatorMitigationDetailsDto.getCi())
                && scoresConfig.getMitigations() != null;
    }
}
