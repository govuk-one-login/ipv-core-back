package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ValidationHelperTest {

    @Nested
    class IpvSessionIdTests {

        @Test
        void acceptsExactly43AllowedChars() {
            var validId = "u7zeydbeSw6vnxBttMRPj-cmlEb4HGc4YxTQR8ORiOo"; // pragma: allowlist secret
            assertEquals(43, validId.length());
            assertTrue(ValidationHelper.isValidIpvSessionId(validId));
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "",
                    "A",
                    "AAAAAAAAAAA",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 44
                })
        void rejectsWrongLength(String input) {
            assertFalse(ValidationHelper.isValidIpvSessionId(input));
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "u7zeydbeSw6vnxBttMRPj-cmlEb4HGc4YxTQR8ORiO!",
                    "u7zeydbeSw6vnxBttMRPj-cmlEb4HGc4YxTQR8ORiO.",
                    "u7zeydbeSw6vnxBttMRPj-cmlEb4HGc4YxTQR8ORiO/", // pragma: allowlist secret
                    "u7zeydbeSw6vnxBttMRPj-cmlEb4HGc4YxTQR8OR O8",
                    "u7zeydbeSw6vnxBttMRPj-cmlEb4HGc4YxTQR8ORiO:"
                })
        void rejectsForbiddenCharacters(String input) {
            assertFalse(ValidationHelper.isValidIpvSessionId(input));
        }

        @Test
        void rejectNullValue() {
            assertFalse(ValidationHelper.isValidIpvSessionId(null));
        }
    }
}
