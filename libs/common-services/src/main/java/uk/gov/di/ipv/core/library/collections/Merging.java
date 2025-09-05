package uk.gov.di.ipv.core.library.collections;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Merging {

    @ExcludeFromGeneratedCoverageReport
    private Merging() {}

    public static <T> List<T> mergeLists(List<T> left, List<T> right) {
        var merged = new ArrayList<T>();

        if (left != null) {
            merged.addAll(left);
        }
        if (right != null) {
            merged.addAll(right);
        }

        return merged;
    }

    public static <K, V> Map<K, V> mergeMaps(Map<K, V> left, Map<K, V> right) {
        var merged = new HashMap<K, V>();

        if (left != null) {
            merged.putAll(left);
        }
        if (right != null) {
            merged.putAll(right);
        }

        return merged;
    }

    public static <T> Set<T> mergeSets(Set<T> left, Set<T> right) {
        var merged = new HashSet<T>();

        if (left != null) {
            merged.addAll(left);
        }
        if (right != null) {
            merged.addAll(right);
        }

        return merged;
    }
}
