package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.createName;

class NameHelperTest {
    @Test
    void shouldDeduplicateNamesWithCaseInsensitivity() {
        // Arrange
        var name1 = createName("martin", "smith");
        var name2 = createName("Martin", "smith");
        var name3 = createName("MARTIN", "smith");
        var name4 = createName("Harry", "smith");
        var names = Set.of(name1, name2, name3, name4);

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(2, deduplicateNames.size());
        assertTrue(deduplicateNames.contains(name4));
    }
}
