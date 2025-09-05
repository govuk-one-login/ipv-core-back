package uk.gov.di.ipv.core.library.collections;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.collections.Merging.mergeLists;
import static uk.gov.di.ipv.core.library.collections.Merging.mergeMaps;
import static uk.gov.di.ipv.core.library.collections.Merging.mergeSets;

class MergingTest {
    private static final ArrayList<String> List1 =
            new ArrayList<>(Arrays.asList("value1", "value2"));
    private static final ArrayList<String> List2 =
            new ArrayList<>(Arrays.asList("value3", "value4"));
    private static final Map<String, String> Map1 = Map.of("key1", "value1", "key2", "value2");
    private static final Map<String, String> Map2 = Map.of("key3", "value3", "key4", "value4");
    private static final HashSet<String> Set1 = new HashSet<>(Arrays.asList("value1", "value2"));
    private static final HashSet<String> Set2 = new HashSet<>(Arrays.asList("value3", "value4"));

    @Test
    void mergingNullListsShouldReturnEmptyList() {

        // Act
        var ret = mergeLists((List<String>) null, (List<String>) null);

        // Assert
        assertEquals(new ArrayList<>(), ret);
    }

    @Test
    void mergingNullListWithListFirstShouldReturnSingleList() {

        // Act
        var ret = mergeLists(List1, (List<String>) null);

        // Assert
        assertEquals(List1, ret);
    }

    @Test
    void mergingNullListWithListSecondShouldReturnSingleList() {

        // Act
        var ret = mergeLists((List<String>) null, List1);

        // Assert
        assertEquals(List1, ret);
    }

    @Test
    void mergingListsShouldReturnAllItems() {

        // Act
        var ret = mergeLists(List1, List2);

        // Assert
        assertEquals(new ArrayList<>(Arrays.asList("value1", "value2", "value3", "value4")), ret);
    }

    @Test
    void mergingNullMapsShouldReturnEmptyMap() {

        // Act
        var ret = mergeMaps((Map<String, String>) null, (Map<String, String>) null);

        // Assert
        assertEquals(new HashMap<>(), ret);
    }

    @Test
    void mergingNullMapWithMapFirstShouldReturnSingleList() {

        // Act
        var ret = mergeMaps(Map1, (Map<String, String>) null);

        // Assert
        assertEquals(Map1, ret);
    }

    @Test
    void mergingNullMapWithMapSecondShouldReturnSingleList() {

        // Act
        var ret = mergeMaps((Map<String, String>) null, Map1);

        // Assert
        assertEquals(Map1, ret);
    }

    @Test
    void mergingMapsShouldReturnAllItems() {

        // Act
        var ret = mergeMaps(Map1, Map2);

        // Assert
        assertEquals(
                Map.of("key1", "value1", "key2", "value2", "key3", "value3", "key4", "value4"),
                ret);
    }

    @Test
    void mergeSetsShouldReturnAllItems() {
        // Act
        var ret = mergeSets(Set1, Set2);

        // Assert
        assertEquals(new HashSet<>(Arrays.asList("value1", "value2", "value3", "value4")), ret);
    }

    @Test
    void mergeSetsShouldReturnAllItemsIfJustGivenLeftSet() {
        // Act
        var ret = mergeSets(Set1, null);

        // Assert
        assertEquals(new HashSet<>(Arrays.asList("value1", "value2")), ret);
    }

    @Test
    void mergeSetsShouldReturnAllItemsIfJustGivenRightSet() {
        // Act
        var ret = mergeSets(null, Set2);

        // Assert
        assertEquals(new HashSet<>(Arrays.asList("value3", "value4")), ret);
    }

    @Test
    void mergeSetsShouldReturnEmptySetIfNoneProvided() {
        // Act
        var ret = mergeSets(null, null);

        // Assert
        assertEquals(Collections.emptySet(), ret);
    }
}
