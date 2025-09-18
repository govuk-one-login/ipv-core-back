package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class NumberHelperTest {

    private static final int DEFAULT = 999;

    @Test
    void returnsDefaultOnNull() {
        assertEquals(DEFAULT, NumberHelper.parseIntOrDefault(null, DEFAULT));
    }

    @ParameterizedTest
    @MethodSource("getValidNumbers")
    void parsesValidNumbers(String input, int expected) {
        assertEquals(expected, NumberHelper.parseIntOrDefault(input, DEFAULT));
    }

    private static Stream<Arguments> getValidNumbers() {
        return Stream.of(
                Arguments.of("0", 0),
                Arguments.of("42", 42),
                Arguments.of("-7", -7),
                Arguments.of("+5", 5),
                Arguments.of("007", 7));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", " 123 ", "abc", "12.3", "0x10"})
    void returnsDefaultOnInvalid(String input) {
        assertEquals(DEFAULT, NumberHelper.parseIntOrDefault(input, DEFAULT));
    }

    @Test
    void returnsDefaultOnOverflowTooLarge() {
        // 2147483648 is MAX_VALUE + 1
        assertEquals(DEFAULT, NumberHelper.parseIntOrDefault("2147483648", DEFAULT));
    }

    @Test
    void returnsDefaultOnOverflowTooSmall() {
        // -2147483649 is MIN_VALUE - 1
        assertEquals(DEFAULT, NumberHelper.parseIntOrDefault("-2147483649", DEFAULT));
    }

    @Test
    void parsesAtBounds() {
        assertEquals(
                Integer.MAX_VALUE,
                NumberHelper.parseIntOrDefault(String.valueOf(Integer.MAX_VALUE), DEFAULT));
        assertEquals(
                Integer.MIN_VALUE,
                NumberHelper.parseIntOrDefault(String.valueOf(Integer.MIN_VALUE), DEFAULT));
    }
}
