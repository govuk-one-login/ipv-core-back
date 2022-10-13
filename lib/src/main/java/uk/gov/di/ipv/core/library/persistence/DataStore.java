package uk.gov.di.ipv.core.library.persistence;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
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
        var key = Key.builder().partitionValue(partitionValue).sortValue(sortValue).build();
        return getItemByKey(key);
    }

    public T getItem(String partitionValue) {
        var key = Key.builder().partitionValue(partitionValue).build();
        return getItemByKey(key);
    }

    public T getItemByIndex(String indexName, String value) throws DynamoDbException {
        DynamoDbIndex<T> index = table.index(indexName);
        var key = Key.builder().partitionValue(value).build();
        var queryConditional = QueryConditional.keyEqualTo(key);
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
        var key = Key.builder().partitionValue(partitionValue).build();
        return table.query(QueryConditional.keyEqualTo(key)).stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }

    public List<T> getItemsWithAttributeLessThanOrEqualValue(
            String partitionValue, String filterAttribute, String filterValue) {
        var queryConditional =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(partitionValue).build());
        AttributeValue expressionValue = AttributeValue.builder().s(filterValue).build();
        var filterExpression =
                Expression.builder()
                        .expression("#a <= :b")
                        .putExpressionName("#a", filterAttribute)
                        .putExpressionValue(":b", expressionValue)
                        .build();
        var queryEnhancedRequest =
                QueryEnhancedRequest.builder()
                        .queryConditional(queryConditional)
                        .filterExpression(filterExpression)
                        .build();
        return table.query(queryEnhancedRequest).stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }

    public T update(T item) {
        return table.updateItem(item);
    }

    public T delete(String partitionValue, String sortValue) {
        var key = Key.builder().partitionValue(partitionValue).sortValue(sortValue).build();
        return delete(key);
    }

    public T delete(String partitionValue) {
        var key = Key.builder().partitionValue(partitionValue).build();
        return delete(key);
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
            var message =
                    new MapMessage()
                            .with("datastore", "Null result retrieved from DynamoDB")
                            .with("table", table.describeTable().table().tableName())
                            .with("field", key.partitionKeyValue().toString());
            LOGGER.warn(message);
        }
        return result;
    }

    private T delete(Key key) {
        return table.deleteItem(key);
    }
}
