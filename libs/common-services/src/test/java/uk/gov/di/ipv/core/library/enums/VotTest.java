package uk.gov.di.ipv.core.library.enums;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2B;

class VotTest {
    @ParameterizedTest
    @MethodSource("votProfiles")
    void shouldGetCorrectStrengthVotWithProfile(Gpg45Profile profile, Vot associatedVot) {
        var result = Vot.fromProfile(profile);
        assertEquals(associatedVot, result);
    }

    private static Stream<Arguments> votProfiles() {
        return Stream.of(
                Arguments.of(L1A, Vot.P1),
                Arguments.of(M1A, Vot.P2),
                Arguments.of(M1B, Vot.P2),
                Arguments.of(M2B, Vot.P2));
    }
}
