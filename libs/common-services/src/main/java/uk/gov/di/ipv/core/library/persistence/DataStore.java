package uk.gov.di.ipv.core.library.persistence;

import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.exceptions.BatchProcessingException;
import uk.gov.di.ipv.core.library.exceptions.ItemAlreadyExistsException;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;

public interface DataStore<T extends PersistenceItem> {

    static <T extends PersistenceItem> DataStore<T> create(
            EnvironmentVariable tableName, Class<T> klass, ConfigService configService) {
        return ConfigService.isLocal()
                ? new InMemoryDataStore<>(tableName.name(), klass)
                : new DynamoDataStore<>(
                        configService.getEnvironmentVariable(tableName),
                        klass,
                        DynamoDataStore.getClient(),
                        configService);
    }

    void create(T item, long ttlSeconds);

    void create(T item);

    void createIfNotExists(T item) throws ItemAlreadyExistsException;

    void createOrUpdate(List<T> items) throws BatchProcessingException;

    T getItem(String partitionValue, String sortValue);

    T getItem(String partitionValue);

    T getItemByIndex(String indexName, String value);

    List<T> getItems(String partitionValue);

    List<T> getItemsWithBooleanAttribute(String partitionValue, String name, boolean value);

    List<T> getItemsBySortKeyPrefix(String partitionValue, String sortPrefix);

    T update(T item);

    T delete(String partitionValue, String sortValue);

    void delete(List<T> items) throws BatchProcessingException;

    void deleteAllByPartition(String partitionValue) throws BatchProcessingException;
}
