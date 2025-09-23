package uk.gov.di.ipv.core.library.persistence;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import uk.gov.di.ipv.core.library.exceptions.ItemAlreadyExistsException;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryDataStore<T extends PersistenceItem> implements DataStore<T> {
    private static final String KEY_SEPARATOR = "/";
    private static final ConcurrentMap<String, Map<String, ?>> TABLES = new ConcurrentHashMap<>();

    private final ConcurrentMap<String, T> records;
    private final Class<T> klass;
    private final Method partitionKeyMethod;
    private final Method sortKeyMethod;

    @SuppressWarnings("unchecked") // Rely on callers to use consistent types per table
    public InMemoryDataStore(String tableName, Class<T> klass) {
        this.records =
                (ConcurrentMap<String, T>)
                        TABLES.computeIfAbsent(tableName, k -> new ConcurrentHashMap<>());
        this.klass = klass;
        this.partitionKeyMethod = findMethodWithAnnotation(klass, DynamoDbPartitionKey.class);
        this.sortKeyMethod = findMethodWithAnnotation(klass, DynamoDbSortKey.class);

        if (this.partitionKeyMethod == null) {
            throw new IllegalArgumentException(
                    "Missing partition key from class " + klass.getName());
        }
    }

    private Method findMethodWithAnnotation(
            Class<T> klass, Class<? extends Annotation> annotationClass) {
        for (var method : klass.getMethods()) {
            if (method.isAnnotationPresent(annotationClass)) {
                return method;
            }
        }
        return null;
    }

    @Override
    public void create(T item, long ttlSeconds) {
        create(item);
    }

    @Override
    public void create(T item) {
        records.put(getKey(item), item);
    }

    @Override
    public void createIfNotExists(T item) throws ItemAlreadyExistsException {
        var key = getKey(item);
        if (records.putIfAbsent(key, item) != null) {
            throw new ItemAlreadyExistsException();
        }
    }

    @Override
    public void createOrUpdate(List<T> items) {
        for (T item : items) {
            records.put(getKey(item), item);
        }
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
                if (value.equals(indexMethod.invoke(item))) {
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

    @SuppressWarnings(
            "java:S3011") // We rely on field access to avoid needing to search for a getter
    @Override
    public List<T> getItemsWithBooleanAttribute(String partitionValue, String name, boolean value) {
        try {
            var field = klass.getDeclaredField(name);
            field.setAccessible(true);
            return records.values().stream()
                    .filter(i -> getPartitionKey(i).equals(partitionValue))
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
        if (sortKeyMethod == null) {
            throw new IllegalArgumentException(
                    "Cannot search by sort key on a record with no sort key");
        }
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
        if (sortKeyMethod == null) {
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
