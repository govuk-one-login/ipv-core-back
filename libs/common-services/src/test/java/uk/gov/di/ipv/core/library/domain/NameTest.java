package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class NameTest {

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
}
