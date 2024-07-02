package uk.gov.di.ipv.core.library.helpers;

import java.util.stream.Collector;
import java.util.stream.Collectors;

public class CollectionHelper {
    private CollectionHelper() {}

    public static <T> Collector<T, ?, T> toSingleton() {
        return Collectors.collectingAndThen(
                Collectors.toList(),
                list -> {
                    if (list.size() != 1) {
                        throw new IllegalStateException("List size is not 1");
                    }
                    return list.get(0);
                });
    }
}
