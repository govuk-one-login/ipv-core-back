package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ListHelperTest {

    private static Stream<Arguments> ShouldPermuteCorrectlyTestCases() {
        return Stream.of(
                Arguments.of(List.of(1), List.of(
                        List.of(1))),
                Arguments.of(List.of(1, 2), List.of(
                        List.of(1, 2),
                        List.of(2, 1))),
                Arguments.of(List.of(1, 2, 3), List.of(
                        List.of(1, 2, 3),
                        List.of(1, 3, 2),
                        List.of(2, 1, 3),
                        List.of(2, 3, 1),
                        List.of(3, 1, 2),
                        List.of(3, 2, 1)))
        );
    }
    @ParameterizedTest
    @MethodSource("ShouldPermuteCorrectlyTestCases")
    void shouldPermuteCorrectly(List<Integer> listToPermute, List<List<Integer>> expectedResults) {

        var result = ListHelper.getPermutations(listToPermute);

        assertTrue(listsOfListsAreEquivalent(result, expectedResults), "Result does not match expected result");
    }

    private <T> boolean listsOfListsAreEquivalent(List<List<T>> a, List<List<T>> b)
    {
        if (a.size() != b.size()) {
            return false;
        }

        return a.stream()
            .allMatch(al -> 
                b.stream()
                    .anyMatch(bl -> listsContainSameElements(al, bl)));
    }

    private static <T> boolean listsContainSameElements(List<T> a, List<T> b) {
        if (a.size() != b.size()) {
            return false;
        }

        return b.equals(a);
    }
}
