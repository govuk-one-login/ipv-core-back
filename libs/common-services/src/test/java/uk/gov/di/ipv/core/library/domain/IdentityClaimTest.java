package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.model.BirthDate;

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

    @Test
    void getNameParts_whenCalledWithMultipleNames_ReturnsOnlyTheFirstNameParts() {
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
        var result = underTest.getNameParts();

        // Assert
        assertEquals(2, result.size());
        assertEquals("FirstNamePart1", result.get(0).getValue());
        assertEquals("FirstNamePart2", result.get(1).getValue());
    }
}
