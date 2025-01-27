package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.createName;

class NameHelperTest {
    @Test
    void shouldDeduplicateNamesWithCaseInsensitivity() {
        // Arrange
        var names =
                Set.of(
                        createName("martin", "smith"),
                        createName("Martin", "Smith"),
                        createName("MARTIN", "SMITH"),
                        createName("Harry", "Smithy"));

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(
                Set.of(createName("martin", "smith"), createName("Harry", "Smithy")),
                deduplicateNames);
    }
}
