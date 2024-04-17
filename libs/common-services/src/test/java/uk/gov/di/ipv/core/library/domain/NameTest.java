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
    void getNameParts_whenCalledWithOneNameWithOneNamePart_ReturnsTheNamePart() {
        // Arrange
        var underTest = new Name(Arrays.asList(new NameParts("SingleNamePart", "dummyType")));

        // Act
        var result = underTest.getNameParts();

        // Assert
        assertEquals(1, result.size());
        assertEquals("SingleNamePart", result.get(0).getValue());
    }

    @Test
    void getNameParts_whenCalledWithOneNameWithMultipleNameParts_ReturnsTheNameParts() {
        // Arrange
        var underTest =
                new Name(
                        Arrays.asList(
                                new NameParts("FirstNamePart", "dummyType"),
                                new NameParts("SecondNamePart", "dummyType2")));

        // Act
        var result = underTest.getNameParts();

        // Assert
        assertEquals(2, result.size());
        assertEquals("FirstNamePart", result.get(0).getValue());
        assertEquals("dummyType", result.get(0).getType());
        assertEquals("SecondNamePart", result.get(1).getValue());
        assertEquals("dummyType2", result.get(1).getType());
    }
}
