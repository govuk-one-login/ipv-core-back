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

    @Nested
    class GovukSigningJourneyIdTests {

        @Test
        void acceptsValidV4() {
            var valid = "40a89427-71f2-4ad5-ac65-41a6b641d308";
            assertTrue(ValidationHelper.isValidGovukSigninJourneyId(valid));
        }

        @Test
        void rejectsUppercase() {
            assertFalse(
                    ValidationHelper.isValidGovukSigninJourneyId(
                            "40A89427-71F2-4AD5-AC65-41A6B641D308"));
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "40a894277-1f2-4ad5-ac65-41a6b641d308",
                    "40a89427-71f24-ad5-ac65-41a6b641d308",
                    "40a89427-71f2-4ad5a-c65-41a6b641d308",
                    "40a89427-71f2-4ad5-ac654-1a6b641d308"
                })
        void rejectsInvalidPartsLength(String input) {
            assertFalse(ValidationHelper.isValidGovukSigninJourneyId(input));
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "40a8942g-71f2-4ad5-ac65-41a6b641d308",
                    "40a89427-71fg-4ad5-ac65-41a6b641d308",
                    "40a89427-71f2-4adg-ac65-41a6b641d308",
                    "40a89427-71f2-4ad5-ac6g-41a6b641d308",
                    "40a89427-71f2-4ad5-ac65-41a6b641d30g"
                })
        void rejectsNoHexCharacters(String input) {
            assertFalse(ValidationHelper.isValidGovukSigninJourneyId(input));
        }

        @Test
        void rejectNullValues() {
            assertFalse(ValidationHelper.isValidGovukSigninJourneyId(null));
        }
    }
}
