package uk.gov.di.ipv.core.selectcri;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.domain.ContractIndicator;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MitigationServiceTest {

    @Mock private ConfigurationService mockConfigurationService;
    @InjectMocks private MitigationService underTest;
    private Map<String, ContraIndicatorScore> a01CiScoresMap;

    @BeforeEach
    void setUp() {
        a01CiScoresMap =
                Map.of(
                        "A01",
                        new ContraIndicatorScore("A01", 2, -2, null, List.of("MJ01", "MJ02")));
    }

    @Test
    void isMitigationPossibleShouldReturnTrueWhenA01CIAndMigrationNotComplete() {
        when(mockConfigurationService.getContraIndicatorScoresMap()).thenReturn(a01CiScoresMap);

        List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetailsDtos =
                List.of(new ContraIndicatorMitigationDetailsDto(ContractIndicator.A01.name()));
        assertTrue(underTest.isMitigationPossible(contraIndicatorMitigationDetailsDtos));
    }

    @Test
    void isMitigationPossibleShouldReturnFalseWhenNoCIs() {
        assertFalse(underTest.isMitigationPossible(Collections.emptyList()));
    }

    @Test
    void isMitigationPossibleShouldReturnFalseWhenCIHasNoMitigations() {
        when(mockConfigurationService.getContraIndicatorScoresMap())
                .thenReturn(Map.of("A01", new ContraIndicatorScore("A01", 0, 0, null, null)));

        List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetailsDtos =
                List.of(new ContraIndicatorMitigationDetailsDto(ContractIndicator.A01.name()));
        assertFalse(underTest.isMitigationPossible(contraIndicatorMitigationDetailsDtos));
    }
}
