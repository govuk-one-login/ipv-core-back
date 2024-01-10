package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IdentityClaimTest {

    @Test
    void getFullName_whenCalledWithMultipleNames_ReturnsOnlyTheFirstName() {
        // Arrange
        var underTest =
                new IdentityClaim(
                        Arrays.asList(
                                new Name(
                                        Arrays.asList(
                                                new NameParts("FirstNamePart1", "dummyType"),
                                                new NameParts("FirstNamePart2", "dummyType"))),
                                new Name(
                                        Arrays.asList(
                                                new NameParts("SecondNamePart1", "dummyType"),
                                                new NameParts("SecondNamePart2", "dummyType")))),
                        Arrays.asList(new BirthDate()));

        // Act
        var result = underTest.getFullName();

        // Assert
        assertEquals("FirstNamePart1 FirstNamePart2", result);
    }
}
