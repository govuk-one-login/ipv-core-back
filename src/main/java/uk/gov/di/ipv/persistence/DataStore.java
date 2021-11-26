package uk.gov.di.ipv.persistence;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.ipv.service.ConfigurationService;

import java.net.URI;

public class DataStore<T> {

    private static final String LOCALHOST_URI = "http://localhost:4567";

    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private final ConfigurationService configurationService;
    private final String tableName;
    private final Class<T> typeParameterClass;

    public DataStore(String tableName, Class<T> typeParameterClass) {
        this.tableName = tableName;
        this.typeParameterClass = typeParameterClass;

        configurationService = ConfigurationService.getInstance();

        DynamoDbClient client = configurationService.isRunningLocally()
                ? createLocalDbClient()
                : DynamoDbClient.create();

        dynamoDbEnhancedClient = DynamoDbEnhancedClient.builder()
                .dynamoDbClient(client)
                .build();
    }

    public DataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient dynamoDbEnhancedClient,
            ConfigurationService configurationService) {
        this.tableName = tableName;
        this.typeParameterClass = typeParameterClass;
        this.dynamoDbEnhancedClient = dynamoDbEnhancedClient;
        this.configurationService = configurationService;
    }

    public void create(T item) {
        getTable().putItem(item);
    }

    public T read(String partitionValue, String sortValue) {
        return read(Key.builder().partitionValue(partitionValue).sortValue(sortValue).build());
    }

    public T read(String partitionValue) {
        return read(Key.builder().partitionValue(partitionValue).build());
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

    private DynamoDbClient createLocalDbClient() {
        return DynamoDbClient.builder()
                .endpointOverride(URI.create(LOCALHOST_URI))
                .region(Region.EU_WEST_2)
                .build();
    }

    private T read(Key key) {
        return getTable().getItem(key);
    }

    private T delete(Key key) {
        return getTable().deleteItem(key);
    }

    private DynamoDbTable<T> getTable() {
        return dynamoDbEnhancedClient.table(tableName, TableSchema.fromBean(this.typeParameterClass));
    }
}
