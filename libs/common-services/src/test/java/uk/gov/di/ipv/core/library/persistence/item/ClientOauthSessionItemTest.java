package uk.gov.di.ipv.core.library.persistence.item;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientOauthSessionItemTest {
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
}
