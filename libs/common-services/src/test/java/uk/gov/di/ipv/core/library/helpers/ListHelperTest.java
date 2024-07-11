package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.model.BirthDate;

import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator.createBirthDate;

class ListHelperTest {

    private static Stream<Arguments> ShouldPermuteCorrectlyTestCases() {
        return Stream.of(
                Arguments.of(List.of(1), List.of(List.of(1))),
                Arguments.of(List.of(1, 2), List.of(List.of(1, 2), List.of(2, 1))),
                Arguments.of(
                        List.of(1, 2, 3),
                        List.of(
                                List.of(1, 2, 3),
                                List.of(1, 3, 2),
                                List.of(2, 1, 3),
                                List.of(2, 3, 1),
                                List.of(3, 1, 2),
                                List.of(3, 2, 1))));
    }

    private static Stream<Arguments> ShouldBatchCorrectlyTestCases() {
        return Stream.of(
                Arguments.of(
                        List.of(1, 2, 3, 4, 5, 6, 7, 8),
                        List.of(List.of(1, 2, 3), List.of(4, 5, 6), List.of(7, 8))));
    }

    @ParameterizedTest
    @MethodSource("ShouldPermuteCorrectlyTestCases")
    void shouldPermuteCorrectly(List<Integer> listToPermute, List<List<Integer>> expectedResults) {

        var result = ListHelper.getPermutations(listToPermute);

        assertThat(result, containsInAnyOrder(expectedResults.toArray()));
    }

    @ParameterizedTest
    @MethodSource("ShouldBatchCorrectlyTestCases")
    void shouldBatchCorrectly(List<Integer> listToPermute, List<List<Integer>> expectedResults) {

        var result = ListHelper.getBatches(listToPermute, 3);

        assertThat(result, containsInAnyOrder(expectedResults.toArray()));
    }

    @Test
    void shouldApplyExtractorToFirstItemInList() {
        var birthDates = List.of(createBirthDate("2000-01-01"), createBirthDate("2024-01-01"));

        var result = ListHelper.extractFromFirstElementOfList(birthDates, BirthDate::getValue);

        assertEquals("2000-01-01", result);
    }

    @Test
    void shouldApplyExtractorToFirstItemInListForNullValue() {
        var birthDates = List.of(createBirthDate(null), createBirthDate("2024-01-01"));

        var result = ListHelper.extractFromFirstElementOfList(birthDates, BirthDate::getValue);

        assertNull(result);
    }

    @Test
    void shouldApplyExtractorToFirstItemInListForEmptyList() {
        var result = ListHelper.extractFromFirstElementOfList(List.of(), BirthDate::getValue);

        assertNull(result);
    }
}
