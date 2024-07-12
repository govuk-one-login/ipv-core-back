package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.P1_JOURNEYS_ENABLED;

@ExtendWith(MockitoExtension.class)
class VtrTest {
    @Mock private ConfigService mockConfigService;

    @ParameterizedTest
    @MethodSource("vtrRequestedVotsByStrength")
    void getRequestedVotsByStrength_ShouldReturnCorrectVots(
            List<String> vtr, List<Vot> expectedRequestedVots) {
        // Arrange
        var underTest = new Vtr(vtr);

        // Act
        var result = underTest.getRequestedVotsByStrengthDescending();

        // Assert
        assertEquals(expectedRequestedVots, result);
    }

    private static Stream<Arguments> vtrRequestedVotsByStrength() {
        return Stream.of(
                Arguments.of(List.of("P1"), List.of(Vot.P1)),
                Arguments.of(List.of("P2"), List.of(Vot.P2)),
                Arguments.of(List.of("P1", "P2"), List.of(Vot.P2, Vot.P1)),
                Arguments.of(
                        List.of("PCL200", "P1", "P2", "PCL250"),
                        List.of(Vot.P2, Vot.PCL250, Vot.PCL200, Vot.P1)));
    }

    @Test
    void
            getLowestStrengthRequestedGpg45Vot_ShouldReturnGpg45Vot_WhenWeakerNonGpg45VotAlsoRequested() {
        // Arrange
        var vtr = List.of("P2", "PCL200");
        var underTest = new Vtr(vtr);

        // Act
        var result = underTest.getLowestStrengthRequestedGpg45Vot(mockConfigService);

        // Assert
        assertEquals(Vot.P2, result);
    }

    @Test
    void getLowestStrengthRequestedGpg45Vot_ShouldIgnoreP1_WhenP1IsDisabled() {
        // Arrange
        var vtr = List.of("P2", "P1");
        var underTest = new Vtr(vtr);
        when(mockConfigService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(false);

        // Act
        var result = underTest.getLowestStrengthRequestedGpg45Vot(mockConfigService);

        // Assert
        assertEquals(Vot.P2, result);
    }

    @Test
    void getLowestStrengthRequestedGpg45Vot_ShouldReturnP1_WhenP1IsEnabled() {
        // Arrange
        var vtr = List.of("P2", "P1");
        var underTest = new Vtr(vtr);
        when(mockConfigService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);

        // Act
        var result = underTest.getLowestStrengthRequestedGpg45Vot(mockConfigService);

        // Assert
        assertEquals(Vot.P1, result);
    }

    @Test
    void getLowestStrengthRequestedVot_ShouldIgnoreP1_WhenP1IsDisabled() {
        // Arrange
        var vtr = List.of("P2", "PCL200", "PCL250", "P1");
        var underTest = new Vtr(vtr);
        when(mockConfigService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(false);

        // Act
        var result = underTest.getLowestStrengthRequestedVot(mockConfigService);

        // Assert
        assertEquals(Vot.PCL200, result);
    }

    @Test
    void getLowestStrengthRequestedVot_ShouldReturnP1_WhenP1IsEnabled() {
        // Arrange
        var vtr = List.of("PCL200", "P1");
        var underTest = new Vtr(vtr);
        when(mockConfigService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);

        // Act
        var result = underTest.getLowestStrengthRequestedVot(mockConfigService);

        // Assert
        assertEquals(Vot.P1, result);
    }
}
