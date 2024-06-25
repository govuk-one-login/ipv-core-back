package uk.gov.di.ipv.core.library.helpers;

import java.util.stream.Collector;
import java.util.stream.Collectors;

public class CollectionHelper {
    public static <T> Collector<T, ?, T> toSingletonOrNullIfEmpty() {
        return Collectors.collectingAndThen(
                Collectors.toList(),
                list -> {
                    if (list.size() > 1) {
                        throw new IllegalStateException("List too large to be singleton");
                    }
                    if (list.isEmpty()) {
                        return null;
                    }
                    return list.get(0);
                });
    }
}
