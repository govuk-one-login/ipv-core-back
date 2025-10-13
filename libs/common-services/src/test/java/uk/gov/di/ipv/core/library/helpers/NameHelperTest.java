package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.createName;

class NameHelperTest {
    @Test
    void shouldNotDeduplicateDifferentNames() {
        // Arrange
        var name1 = createName("martin", "smith");
        var name2 = createName("martin", "jones");
        var name3 = createName("john", "smith");
        var names = Set.of(name1, name2, name3);

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(3, deduplicateNames.size());
    }

    @Test
    void shouldNotDeduplicateAcrossGivenAndFamilyNames() {
        // Arrange
        var name1 = createName(new String[] {"Martin", "John"}, new String[] {"Smith"});
        var name2 = createName(new String[] {"Martin"}, new String[] {"John", "Smith"});
        var names = Set.of(name1, name2);

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(2, deduplicateNames.size());
    }

    @Test
    void shouldDeduplicateNamesWithDifferentCases() {
        // Arrange
        var name1 = createName("martin", "smith");
        var name2 = createName("MARTIN", "smith");
        var name3 = createName("martin", "SMITH");
        var name4 = createName("MARTIN", "SMITH");
        var names = Set.of(name1, name2, name3, name4);

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(1, deduplicateNames.size());
    }

    @Test
    void shouldDeduplicateNamesWithApostrophes() {
        // Arrange
        var name1 = createName("Martin", "O'Toole");
        var name2 = createName("Martin", "O’Toole");
        var name3 = createName("Martin", "OToole");
        var name4 = createName("M'artin", "OToole");
        var name5 = createName("M’artin", "OToole");
        var names = Set.of(name1, name2, name3, name4, name5);

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(1, deduplicateNames.size());
    }

    @Test
    void shouldDeduplicateNamesWithAccents() {
        // Arrange
        var name1 = createName("José", "Mourinho");
        var name2 = createName("Jose", "Mourinho");
        var name3 = createName("Jose", "Mourinhó");
        var names = Set.of(name1, name2, name3);

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(1, deduplicateNames.size());
    }

    @Test
    void shouldDeduplicateHyphenatedNames() {
        // Arrange
        var name1 = createName("Anne-Marie", "Alicia-Lopez");
        var name2 = createName("Anne-Marie", "Alicia Lopez");
        var name3 = createName("Anne-Marie", new String[] {"Alicia", "Lopez"});
        var name4 = createName("Anne Marie", "Alicia-Lopez");
        var name5 = createName(new String[] {"Anne", "Marie"}, "Alicia-Lopez");
        var names = Set.of(name1, name2, name3, name4, name5);

        // Act
        var deduplicateNames = NameHelper.deduplicateNames(names);

        // Assert
        assertEquals(1, deduplicateNames.size());
    }
}
