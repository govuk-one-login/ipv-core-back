package uk.gov.di.ipv.core.library.persistence;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.exceptions.ItemAlreadyExistsException;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryDataStore<T extends PersistenceItem> implements DataStore<T> {
    private static final String KEY_SEPARATOR = "/";
    private static final Map<String, Map<String, ?>> TABLES = new HashMap<>();

    private final Map<String, T> records;
    private final Class<T> klass;
    private final Method partitionKeyMethod;
    private final Method sortKeyMethod;
    private final boolean hasSortKey;

    @SuppressWarnings("unchecked") // Rely on callers to use consistent types per table
    public InMemoryDataStore(String tableName, Class<T> klass) {
        Method partitionKey = null;
        Method sortKey = null;
        for (var method : klass.getMethods()) {
            if (method.isAnnotationPresent(DynamoDbPartitionKey.class)) {
                partitionKey = method;
            }
            if (method.isAnnotationPresent(DynamoDbSortKey.class)) {
                sortKey = method;
            }
        }
        if (partitionKey == null) {
            throw new IllegalArgumentException(
                    "Missing partition key from class " + klass.getName());
        }

        this.records =
                (HashMap<String, T>) TABLES.computeIfAbsent(tableName, (k) -> new HashMap<>());
        this.klass = klass;
        this.partitionKeyMethod = partitionKey;
        this.sortKeyMethod = sortKey;
        this.hasSortKey = sortKey != null;
    }

    @Override
    public void create(T item, ConfigurationVariable tableTtl) {
        create(item);
    }

    @Override
    public void create(T item) {
        records.put(getKey(item), item);
    }

    @Override
    public void createIfNotExists(T item) throws ItemAlreadyExistsException {
        var key = getKey(item);
        if (records.containsKey(key)) {
            throw new ItemAlreadyExistsException();
        }
        create(item);
    }

    @Override
    public T getItem(String partitionValue, String sortValue) {
        return records.get(getKey(partitionValue, sortValue));
    }

    @Override
    public T getItem(String partitionValue) {
        return records.get(getKey(partitionValue, null));
    }

    @Override
    public T getItem(String partitionValue, boolean warnOnNull) {
        return getItem(partitionValue);
    }

    @Override
    public T getItemByIndex(String indexName, String value) {
        Method indexMethod = null;
        for (var method : klass.getMethods()) {
            if (method.isAnnotationPresent(DynamoDbSecondaryPartitionKey.class)) {
                var annotation = method.getAnnotation(DynamoDbSecondaryPartitionKey.class);
                if (Arrays.asList(annotation.indexNames()).contains(indexName)) {
                    indexMethod = method;
                }
            }
        }
        if (indexMethod == null) {
            throw new IllegalArgumentException("Missing index " + indexName);
        }

        for (var item : records.values()) {
            try {
                if (indexMethod.invoke(item).toString().equals(value)) {
                    return item;
                }
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new IllegalArgumentException("Could not access index " + indexName);
            }
        }
        return null;
    }

    @Override
    public List<T> getItems(String partitionValue) {
        return records.values().stream()
                .filter(i -> getPartitionKey(i).equals(partitionValue))
                .toList();
    }

    @Override
    public List<T> getItemsWithBooleanAttribute(String partitionValue, String name, boolean value) {
        try {
            var field = klass.getDeclaredField(name);
            field.setAccessible(true);
            return records.values().stream()
                    .filter(
                            i -> {
                                try {
                                    return Boolean.valueOf(value).equals(field.get(i));
                                } catch (IllegalAccessException e) {
                                    throw new IllegalArgumentException(
                                            "Could not access attribute " + name, e);
                                }
                            })
                    .toList();
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not find boolean attribute " + name, e);
        }
    }

    @Override
    public List<T> getItemsBySortKeyPrefix(String partitionValue, String sortPrefix) {
        return records.values().stream()
                .filter(
                        i ->
                                getPartitionKey(i).equals(partitionValue)
                                        && getSortKey(i).startsWith(sortPrefix))
                .toList();
    }

    @Override
    public T update(T item) {
        records.put(getKey(item), item);
        return item;
    }

    @Override
    public T delete(String partitionValue, String sortValue) {
        return records.remove(getKey(partitionValue, sortValue));
    }

    @Override
    public void delete(List<T> items) {
        items.forEach(i -> records.remove(getKey(i)));
    }

    @Override
    public void deleteAllByPartition(String partitionValue) {
        records.values().removeIf(i -> getPartitionKey(i).equals(partitionValue));
    }

    private String getKey(String partitionKey, String sortKey) {
        var key = partitionKey;
        if (sortKey != null) {
            key = key + KEY_SEPARATOR + sortKey;
        }
        return key;
    }

    private String getPartitionKey(T item) {
        try {
            return partitionKeyMethod.invoke(item).toString();
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new IllegalArgumentException("Could not access key", e);
        }
    }

    private String getSortKey(T item) {
        if (!hasSortKey) {
            return null;
        }
        try {
            return sortKeyMethod.invoke(item).toString();
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new IllegalArgumentException("Could not access key", e);
        }
    }

    private String getKey(T item) {
        return getKey(getPartitionKey(item), getSortKey(item));
    }
}
