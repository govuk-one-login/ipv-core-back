package uk.gov.di.ipv.core.library.persistence.item;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class ClientOauthSessionItemTest {
    @Mock private ConfigService mockConfigService;

    @ParameterizedTest
    @MethodSource("vtrRequestedVotsByStrength")
    void getRequestedVotsByStrength_ShouldReturnCorrectVots(
            List<String> vtr, List<Vot> expectedRequestedVots) {
        // Arrange
        var underTest = ClientOAuthSessionItem.builder().vtr(vtr).build();

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
    void updateTargetVotForGpg45Only_ShouldUpdateSessionWithNewTargetVot_WhenP1IsDisabled()
            throws HttpResponseExceptionWithErrorBody {
        // Arrange
        var vtr = List.of("P2", "PCL200", "PCL250", "P1");
        var clientOAuthSessionItem = ClientOAuthSessionItem.builder().vtr(vtr).build();
        var isP1JourneysEnabled = false;

        // Act
        clientOAuthSessionItem.updateTargetVotForGpg45Only(isP1JourneysEnabled);

        // Assert
        assertEquals(Vot.P2, clientOAuthSessionItem.getTargetVot());
    }

    @Test
    void updateTargetVotForGpg45Only_ShouldUpdateSessionWithNewTargetVot_WhenP1IsEnabled()
            throws HttpResponseExceptionWithErrorBody {
        // Arrange
        var vtr = List.of("P2", "PCL200", "PCL250", "P1");
        var clientOAuthSessionItem = ClientOAuthSessionItem.builder().vtr(vtr).build();
        var isP1JourneysEnabled = true;

        // Act
        clientOAuthSessionItem.updateTargetVotForGpg45Only(isP1JourneysEnabled);

        // Assert
        assertEquals(Vot.P1, clientOAuthSessionItem.getTargetVot());
    }

    @Test
    void getLowestStrengthRequestedVot_ShouldIgnoreP1_WhenP1IsDisabled()
            throws HttpResponseExceptionWithErrorBody {
        // Arrange
        var vtr = List.of("P2", "PCL200", "PCL250", "P1");
        var underTest = ClientOAuthSessionItem.builder().vtr(vtr).build();
        var isP1JourneysEnabled = false;

        // Act
        var result = underTest.getLowestStrengthRequestedVot(isP1JourneysEnabled);

        // Assert
        assertEquals(Vot.PCL200, result);
    }

    @Test
    void getLowestStrengthRequestedVot_ShouldReturnP1_WhenP1IsEnabled()
            throws HttpResponseExceptionWithErrorBody {
        // Arrange
        var vtr = List.of("PCL200", "P1");
        var underTest = ClientOAuthSessionItem.builder().vtr(vtr).build();
        var isP1JourneysEnabled = true;

        // Act
        var result = underTest.getLowestStrengthRequestedVot(isP1JourneysEnabled);

        // Assert
        assertEquals(Vot.P1, result);
    }

    @Test
    void constructor_ShouldSetTargetVot_WhenP1IsDisabled()
            throws HttpResponseExceptionWithErrorBody {
        // Arrange
        var vtr = List.of("P2", "PCL200", "PCL250", "P1");
        var isP1JourneysEnabled = false;

        // Act
        var clientOauthSessionItem =
                new ClientOAuthSessionItem(
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        vtr,
                        null,
                        isP1JourneysEnabled);

        // Assert
        assertEquals(Vot.PCL200, clientOauthSessionItem.getTargetVot());
    }

    @Test
    void constructor_ShouldSetTargetVot_WhenP1IsEnabled()
            throws HttpResponseExceptionWithErrorBody {
        // Arrange
        var vtr = List.of("P2", "PCL200", "PCL250", "P1");
        var isP1JourneysEnabled = true;

        // Act
        var clientOauthSessionItem =
                new ClientOAuthSessionItem(
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        vtr,
                        null,
                        isP1JourneysEnabled);

        // Assert
        assertEquals(Vot.P1, clientOauthSessionItem.getTargetVot());
    }
}
