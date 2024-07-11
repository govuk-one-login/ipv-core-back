package uk.gov.di.ipv.core.library.helpers;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.IntStream;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;

public class ListHelper {

    @ExcludeFromGeneratedCoverageReport
    private ListHelper() {
        throw new IllegalStateException("Utility class");
    }

    // Be careful with this method. The number of permutations grows extremely quickly
    // with increasing size of the original list.
    public static <T> List<List<T>> getPermutations(List<T> original) {
        var size = original.size();

        var clone = new ArrayList<>(original);
        var permutations = new ArrayList<List<T>>();

        int[] indexes = new int[size];

        permutations.add(clone);

        int i = 0;
        while (i < size) {
            if (indexes[i] < i) {
                clone = new ArrayList<>(clone);
                swap(clone, i % 2 == 0 ? 0 : indexes[i], i);
                permutations.add(clone);
                indexes[i]++;
                i = 0;
            } else {
                indexes[i] = 0;
                i++;
            }
        }

        return permutations;
    }

    public static <T> List<List<T>> getBatches(List<T> collection, int batchSize) {
        return IntStream.iterate(0, i -> i < collection.size(), i -> i + batchSize)
                .mapToObj(i -> collection.subList(i, Math.min(i + batchSize, collection.size())))
                .toList();
    }

    private static <T> void swap(List<T> elements, int a, int b) {
        T tmp = elements.get(a);
        elements.set(a, elements.get(b));
        elements.set(b, tmp);
    }

    public static <T, R> R extractFromFirstElementOfList(List<T> list, Function<T, R> extractor) {
        return isNullOrEmpty(list) ? null : extractor.apply(list.get(0));
    }
}
