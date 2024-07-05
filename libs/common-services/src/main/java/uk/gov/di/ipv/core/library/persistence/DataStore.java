package uk.gov.di.ipv.core.library.persistence;

import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.exceptions.BatchDeleteException;
import uk.gov.di.ipv.core.library.exceptions.ItemAlreadyExistsException;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;

public interface DataStore<T extends PersistenceItem> {

    static <T extends PersistenceItem> DataStore<T> create(
            String tableName, Class<T> klass, ConfigService configService) {
        return configService.isLocalDev()
                ? new InMemoryDataStore<>(klass)
                : new DynamoDataStore<>(
                        tableName, klass, DynamoDataStore.getClient(), configService);
    }

    void create(T item, ConfigurationVariable tableTtl);

    void create(T item);

    void createIfNotExists(T item) throws ItemAlreadyExistsException;

    T getItem(String partitionValue, String sortValue);

    T getItem(String partitionValue);

    T getItem(String partitionValue, boolean warnOnNull);

    T getItemByIndex(String indexName, String value);

    List<T> getItems(String partitionValue);

    List<T> getItemsWithBooleanAttribute(String partitionValue, String name, boolean value);

    List<T> getItemsBySortKeyPrefix(String partitionValue, String sortPrefix);

    T update(T item);

    T delete(String partitionValue, String sortValue);

    void delete(List<T> items) throws BatchDeleteException;

    void deleteAllByPartition(String partitionValue) throws BatchDeleteException;
}
