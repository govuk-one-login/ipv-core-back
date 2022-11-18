package uk.gov.di.ipv.core.selectcri;

import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.dto.MitigationJourneyDetailsDto;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class MitigationService {

    private final ConfigurationService configurationService;

    public MitigationService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public boolean isMitigatable(
            List<MitigationJourneyDetailsDto> mitigationJourneyDetailsDtoList) {

        List<MitigationJourneyDetailsDto> mitigatableItems =
                mitigationJourneyDetailsDtoList.stream()
                        .filter(item -> !item.isComplete() && canBeMitigatedByConfig(item))
                        .collect(Collectors.toList());
        return !mitigatableItems.isEmpty();
    }

    private boolean canBeMitigatedByConfig(MitigationJourneyDetailsDto item) {
        Map<String, ContraIndicatorScore> contraIndicatorScoresMap =
                configurationService.getContraIndicatorScoresMap();
        ContraIndicatorScore scoresConfig =
                contraIndicatorScoresMap.get(item.getMitigationJourneyId().name());
        return scoresConfig.getCi().equals(item.getMitigationJourneyId().name())
                && !scoresConfig.getMitigations().isEmpty();
    }
}
