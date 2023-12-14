package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class IdentityClaimTest {

    @Test
    void getFullName_whenCalledWithOneNameWithOneNamePart_ReturnsTheNamePart() {
        // Arrange
        var underTest = new IdentityClaim(
                Arrays.asList(
                    new Name(
                        Arrays.asList(
                                new NameParts("SingleNamePart", "dummyType")))),
                Arrays.asList(
                        new BirthDate()));

        // Act
        var result = underTest.getFullName();

        // Assert
        assertEquals("SingleNamePart", result);
    }

    @Test
    void getFullName_whenCalledWithOneNameWithMultipleNameParts_ReturnsTheNamePartsConcatenated() {
        // Arrange
        var underTest = new IdentityClaim(
                Arrays.asList(
                        new Name(
                                Arrays.asList(
                                        new NameParts("FirstNamePart", "dummyType"),
                                        new NameParts("SecondNamePart", "dummyType")))),
                Arrays.asList(
                        new BirthDate()));

        // Act
        var result = underTest.getFullName();

        // Assert
        assertEquals("FirstNamePart SecondNamePart", result);
    }

    @Test
    void getFullName_whenCalledWithMultipleNames_ReturnsOnlyTheFirstName() {
        // Arrange
        var underTest = new IdentityClaim(
                Arrays.asList(
                        new Name(
                                Arrays.asList(
                                        new NameParts("FirstNamePart1", "dummyType"),
                                        new NameParts("FirstNamePart2", "dummyType"))),
                        new Name(
                                Arrays.asList(
                                        new NameParts("SecondNamePart1", "dummyType"),
                                        new NameParts("SecondNamePart2", "dummyType")))),
                Arrays.asList(
                        new BirthDate()));

        // Act
        var result = underTest.getFullName();

        // Assert
        assertEquals("FirstNamePart1 FirstNamePart2", result);
    }
}
