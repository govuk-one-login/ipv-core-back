package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NameTest {

    @Test
    void getFullName_whenCalledWithOneNameWithOneNamePart_ReturnsTheNamePart() {
        // Arrange
        var underTest = new Name(Arrays.asList(new NameParts("SingleNamePart", "dummyType")));

        // Act
        var result = underTest.getFullName();

        // Assert
        assertEquals("SingleNamePart", result);
    }

    @Test
    void getFullName_whenCalledWithOneNameWithMultipleNameParts_ReturnsTheNamePartsConcatenated() {
        // Arrange
        var underTest =
                new Name(
                        Arrays.asList(
                                new NameParts("FirstNamePart", "dummyType"),
                                new NameParts("SecondNamePart", "dummyType")));

        // Act
        var result = underTest.getFullName();

        // Assert
        assertEquals("FirstNamePart SecondNamePart", result);
    }
    @Test
    void getFormattedName_whenCalledWithOneNameWithOneNamePart_ReturnsTheNamePart() {
        // Arrange
        var underTest = new Name(Arrays.asList(new NameParts("SingleNamePart", "dummyType")));

        // Act
        var result = underTest.getFormattedName();

        // Assert
        assertEquals("SingleNamePart", result.get("dummyType"));
    }

    @Test
    void getFormattedName_whenCalledWithOneNameWithMultipleNameParts_ReturnsTheNameParts() {
        // Arrange
        var underTest =
                new Name(
                        Arrays.asList(
                                new NameParts("FirstNamePart", "dummyType"),
                                new NameParts("SecondNamePart", "dummyType2")));

        // Act
        var result = underTest.getFormattedName();

        // Assert
        assertEquals("FirstNamePart", result.get("dummyType"));
        assertEquals("SecondNamePart", result.get("dummyType2"));
    }
}
