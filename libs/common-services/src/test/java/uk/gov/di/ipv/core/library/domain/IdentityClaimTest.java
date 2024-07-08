package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.NamePart;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.NamePartGenerator.createNamePart;

class IdentityClaimTest {

    @Test
    void getFullName_whenCalledWithMultipleNames_ReturnsOnlyTheFirstName() {
        // Arrange
        var underTest =
                new IdentityClaim(
                        Arrays.asList(
                                NameGenerator.createName(
                                        Arrays.asList(
                                                createNamePart(
                                                        "FirstNamePart1",
                                                        NamePart.NamePartType.GIVEN_NAME),
                                                createNamePart(
                                                        "FirstNamePart2",
                                                        NamePart.NamePartType.FAMILY_NAME))),
                                NameGenerator.createName(
                                        Arrays.asList(
                                                createNamePart(
                                                        "SecondNamePart1",
                                                        NamePart.NamePartType.GIVEN_NAME),
                                                createNamePart(
                                                        "SecondNamePart2",
                                                        NamePart.NamePartType.FAMILY_NAME)))),
                        List.of(new BirthDate()));

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
                                NameGenerator.createName(
                                        Arrays.asList(
                                                createNamePart(
                                                        "FirstNamePart1",
                                                        NamePart.NamePartType.GIVEN_NAME),
                                                createNamePart(
                                                        "FirstNamePart2",
                                                        NamePart.NamePartType.FAMILY_NAME))),
                                NameGenerator.createName(
                                        Arrays.asList(
                                                createNamePart(
                                                        "SecondNamePart1",
                                                        NamePart.NamePartType.GIVEN_NAME),
                                                createNamePart(
                                                        "SecondNamePart2",
                                                        NamePart.NamePartType.FAMILY_NAME)))),
                        List.of(new BirthDate()));

        // Act
        var result = underTest.getNameParts();

        // Assert
        assertEquals(2, result.size());
        assertEquals("FirstNamePart1", result.get(0).getValue());
        assertEquals("FirstNamePart2", result.get(1).getValue());
    }
}
