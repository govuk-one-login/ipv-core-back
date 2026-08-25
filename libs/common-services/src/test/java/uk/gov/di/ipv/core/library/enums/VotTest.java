package uk.gov.di.ipv.core.library.enums;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.V3A;

class VotTest {
    @ParameterizedTest
    @MethodSource("votProfiles")
    void shouldGetCorrectStrengthVotWithProfile(Gpg45Profile profile, Vot associatedVot) {
        // Act
        var result = Vot.fromGpg45Profile(profile);

        // Assert
        assertEquals(associatedVot, result);
    }

    private static Stream<Arguments> votProfiles() {
        return Stream.of(
                Arguments.of(L1A, Vot.P1),
                Arguments.of(M1A, Vot.P2),
                Arguments.of(M1B, Vot.P2),
                Arguments.of(M2B, Vot.P2));
    }

    @Test
    void shouldThrowForInvalidProfile() {
        // Act
        var exception = assertThrows(IllegalStateException.class, () -> Vot.fromGpg45Profile(V3A));

        // Assert
        assertEquals("List size is not 1", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"P0", "P1", "P2", "P3", "p1", " p2 ", "P3 "})
    void parseShouldReturnCorrectVotForValidStrings(String input) {
        // Act
        Optional<Vot> result = Vot.parse(input);

        // Assert
        assertTrue(result.isPresent());
        assertEquals(input.trim().toUpperCase(), result.get().name());
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid", "Cl.Cm.P2", "c1.cm.P2", "", "   "})
    void parseShouldReturnEmptyForInvalidStrings(String input) {
        // Act
        Optional<Vot> result = Vot.parse(input);

        // Assert
        assertTrue(result.isEmpty());
    }

    @Test
    void parseShouldReturnEmptyForNullInput() {
        // Act
        Optional<Vot> result = Vot.parse(null);

        // Assert
        assertTrue(result.isEmpty());
    }
}
