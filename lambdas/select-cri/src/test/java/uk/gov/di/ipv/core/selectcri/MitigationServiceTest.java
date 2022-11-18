package uk.gov.di.ipv.core.selectcri;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.domain.MitigationJourneyId;
import uk.gov.di.ipv.core.library.dto.MitigationJourneyDetailsDto;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MitigationServiceTest {

    @Mock private ConfigurationService mockConfigurationService;
    @InjectMocks private MitigationService underTest;

    @BeforeEach
    void setUp() {}

    @Test
    void shouldTrueWhenA01CIAndMigrationNotComplete() {
        Map<String, ContraIndicatorScore> ciScoresMap =
                Map.of(
                        "A01",
                        new ContraIndicatorScore("A01", 2, -2, null, List.of("MJ01", "MJ02")));
        when(mockConfigurationService.getContraIndicatorScoresMap()).thenReturn(ciScoresMap);

        List<MitigationJourneyDetailsDto> mitigationJourneyDetailsDtoList =
                List.of(new MitigationJourneyDetailsDto(MitigationJourneyId.A01, false));
        assertTrue(underTest.isMitigatable(mitigationJourneyDetailsDtoList));
    }
}
