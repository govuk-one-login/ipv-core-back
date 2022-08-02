package uk.gov.di.ipv.core.library.persistence;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.DynamodbItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

public class DataStore<T extends DynamodbItem> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String LOCALHOST_URI = "http://localhost:4567";
    private static boolean isRunningLocally;

    private final Class<T> typeParameterClass;
    private final ConfigurationService configurationService;
    private final DynamoDbTable<T> table;

    public DataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient dynamoDbEnhancedClient,
            boolean isRunningLocally,
            ConfigurationService configurationService) {
        this.typeParameterClass = typeParameterClass;
        this.configurationService = configurationService;
        DataStore.isRunningLocally = isRunningLocally;
        this.table =
                dynamoDbEnhancedClient.table(
                        tableName, TableSchema.fromBean(this.typeParameterClass));
    }

    public static DynamoDbEnhancedClient getClient(boolean isRunningLocally) {
        DynamoDbClient client =
                isRunningLocally
                        ? createLocalDbClient()
                        : DynamoDbClient.builder()
                                .httpClient(UrlConnectionHttpClient.create())
                                .build();

        return DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
    }

    public void create(T item) {
        item.setTtl(
                Instant.now()
                        .plusSeconds(
                                Long.parseLong(
                                        configurationService.getSsmParameter(BACKEND_SESSION_TTL)))
                        .getEpochSecond());
        table.putItem(item);
    }

    public T getItem(String partitionValue, String sortValue) {
        return getItemByKey(
                Key.builder().partitionValue(partitionValue).sortValue(sortValue).build());
    }

    public T getItem(String partitionValue) {
        return getItemByKey(Key.builder().partitionValue(partitionValue).build());
    }

    public T getItemByIndex(String indexName, String value) throws DynamoDbException {
        DynamoDbIndex<T> index = table.index(indexName);
        var attVal = AttributeValue.builder().s(value).build();
        var queryConditional =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(attVal).build());
        var queryEnhancedRequest =
                QueryEnhancedRequest.builder().queryConditional(queryConditional).build();

        List<T> results =
                index.query(queryEnhancedRequest).stream()
                        .flatMap(page -> page.items().stream())
                        .collect(Collectors.toList());

        if (Objects.isNull(results) || results.isEmpty()) {
            return null;
        }
        return results.get(0);
    }

    public List<T> getItems(String partitionValue) {
        return table
                .query(
                        QueryConditional.keyEqualTo(
                                Key.builder().partitionValue(partitionValue).build()))
                .stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }

    public T update(T item) {
        return table.updateItem(item);
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
                .httpClient(UrlConnectionHttpClient.create())
                .region(Region.EU_WEST_2)
                .build();
    }

    private T getItemByKey(Key key) {
        T result = table.getItem(key);
        if (result == null) {
            LoggingUtils.appendKey(
                    LogHelper.LogField.DYNAMODB_TABLE_NAME.getFieldName(),
                    table.describeTable().table().tableName());
            LoggingUtils.appendKey(
                    LogHelper.LogField.DYNAMODB_KEY_VALUE.getFieldName(),
                    key.partitionKeyValue().toString());
            LOGGER.warn("Null result retrieved out of DynamoDB");
            LoggingUtils.removeKeys(
                    LogHelper.LogField.DYNAMODB_TABLE_NAME.getFieldName(),
                    LogHelper.LogField.DYNAMODB_KEY_VALUE.getFieldName());
        }
        return result;
    }

    private T delete(Key key) {
        return table.deleteItem(key);
    }
}
