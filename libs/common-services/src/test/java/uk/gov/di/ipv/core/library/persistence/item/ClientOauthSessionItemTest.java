package uk.gov.di.ipv.core.library.persistence.item;

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
class ClientOauthSessionItemTest {

    @Mock private ConfigService mockConfigService;

    @ParameterizedTest
    @MethodSource("vtrRequestedVotsByStrength")
    void getRequestedVotsByStrengthShouldReturnCorrectVots(
            List<String> vtr, List<Vot> expectedRequestedVots) {
        // Arrange
        var underTest = ClientOAuthSessionItem.builder().vtr(vtr).build();

        // Act
        var result = underTest.getRequestedVotsByStrength();

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
        var underTest = ClientOAuthSessionItem.builder().vtr(vtr).build();

        // Act
        var result = underTest.getLowestStrengthRequestedGpg45Vot(mockConfigService);

        // Assert
        assertEquals(Vot.P2, result);
    }

    @Test
    void getLowestStrengthRequestedGpg45Vot_ShouldIgnoreP1_WhenP1IsDisabled() {
        // Arrange
        var vtr = List.of("P2", "P1");
        var underTest = ClientOAuthSessionItem.builder().vtr(vtr).build();
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
        var underTest = ClientOAuthSessionItem.builder().vtr(vtr).build();
        when(mockConfigService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);

        // Act
        var result = underTest.getLowestStrengthRequestedGpg45Vot(mockConfigService);

        // Assert
        assertEquals(Vot.P1, result);
    }
}
