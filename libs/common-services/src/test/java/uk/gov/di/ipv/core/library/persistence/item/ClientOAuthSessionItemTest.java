package uk.gov.di.ipv.core.library.persistence.item;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;

class ClientOAuthSessionItemTest {
    private ClientOAuthSessionItem underTest;

    @BeforeEach
    void setUp() {
        underTest = new ClientOAuthSessionItem();
    }

    private static Stream<Arguments> scopeParameters() {
        return Stream.of(
                Arguments.of("scope1", List.of("scope1")),
                Arguments.of("scope1 scope2", List.of("scope1", "scope2")));
    }

    @ParameterizedTest
    @MethodSource("scopeParameters")
    void shouldParseScopeIntoClaims(String scope, List<String> claims) {
        // Arrange
        underTest.setScope(scope);

        // Act
        var result = underTest.getScopeClaims();

        // Assert
        assertThat(result, Matchers.containsInAnyOrder(claims.toArray()));
    }

    private static Stream<Arguments> reverificationParameters() {
        return Stream.of(
                Arguments.of(ScopeConstants.REVERIFICATION, true),
                Arguments.of("scope1 scope2", false));
    }

    @ParameterizedTest
    @MethodSource("reverificationParameters")
    void shouldDetectReverification(String scope, boolean expectedIsReverification) {
        // Arrange
        underTest.setScope(scope);

        // Act
        var result = underTest.isReverification();

        // Assert
        assertEquals(expectedIsReverification, result);
    }

    private static Stream<Arguments> vtrParameters() {
        return Stream.of(
                Arguments.of(null, Collections.emptyList()),
                Arguments.of(Collections.emptyList(), Collections.emptyList()),
                Arguments.of(List.of("P1"), List.of(P1)),
                Arguments.of(List.of("P1", "P2"), List.of(P1, P2)));
    }

    @ParameterizedTest
    @MethodSource("vtrParameters")
    void shouldParseVots(List<String> vtr, List<Vot> expectedVots) {
        // Arrange
        underTest.setVtr(vtr);

        // Act
        var result = underTest.getVtrAsVots();

        // Assert
        assertThat(result, Matchers.containsInAnyOrder(expectedVots.toArray()));
    }
}
