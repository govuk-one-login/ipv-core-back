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
            List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetailsDtos) {

        List<ContraIndicatorMitigationDetailsDto> mitigationPossibleItems =
                contraIndicatorMitigationDetailsDtos.stream()
                        .filter(this::canBeMitigatedByConfig)
                        .collect(Collectors.toList());
        return !mitigationPossibleItems.isEmpty();
    }

    private boolean canBeMitigatedByConfig(ContraIndicatorMitigationDetailsDto item) {
        Map<String, ContraIndicatorScore> contraIndicatorScoresMap =
                configurationService.getContraIndicatorScoresMap();
        ContraIndicatorScore scoresConfig = contraIndicatorScoresMap.get(item.getCi().name());
        return scoresConfig.getCi().equals(item.getCi().name())
                && !scoresConfig.getMitigations().isEmpty();
    }
}
