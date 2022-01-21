package uk.gov.di.ipv.core.library.persistence;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

public class DataStore<T> {

    private static final String LOCALHOST_URI = "http://localhost:4567";
    private static ConfigurationService configurationService;

    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private final String tableName;
    private final Class<T> typeParameterClass;

    public DataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient dynamoDbEnhancedClient,
            ConfigurationService configurationService) {
        this.tableName = tableName;
        this.typeParameterClass = typeParameterClass;
        this.dynamoDbEnhancedClient = dynamoDbEnhancedClient;
        DataStore.configurationService = configurationService;
    }

    public static DynamoDbEnhancedClient getClient() {
        DynamoDbClient client =
                configurationService.isRunningLocally()
                        ? createLocalDbClient()
                        : DynamoDbClient.create();

        return DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
    }

    public void create(T item) {
        getTable().putItem(item);
    }

    public T getItem(String partitionValue, String sortValue) {
        return getItemByKey(
                Key.builder().partitionValue(partitionValue).sortValue(sortValue).build());
    }

    public T getItem(String partitionValue) {
        return getItemByKey(Key.builder().partitionValue(partitionValue).build());
    }

    public List<T> getItems(String partitionValue) {
        return getTable()
                .query(
                        QueryConditional.keyEqualTo(
                                Key.builder().partitionValue(partitionValue).build()))
                .stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }

    public T update(T item) {
        return getTable().updateItem(item);
    }

    public T delete(String partitionValue, String sortValue) {
        return delete(Key.builder().partitionValue(partitionValue).sortValue(sortValue).build());
    }

    public T delete(String partitionValue) {
        return delete(Key.builder().partitionValue(partitionValue).build());
    }

    private static DynamoDbClient createLocalDbClient() {
        return DynamoDbClient.builder()
                .endpointOverride(URI.create(LOCALHOST_URI))
                .region(Region.EU_WEST_2)
                .build();
    }

    private T getItemByKey(Key key) {
        return getTable().getItem(key);
    }

    private T delete(Key key) {
        return getTable().deleteItem(key);
    }

    private DynamoDbTable<T> getTable() {
        return dynamoDbEnhancedClient.table(
                tableName, TableSchema.fromBean(this.typeParameterClass));
    }
}
