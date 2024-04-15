package uk.gov.di.ipv.core.library.persistence;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.PutItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.exceptions.DataStoreException;
import uk.gov.di.ipv.core.library.persistence.item.DynamodbItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.StringJoiner;

public class DataStore<T extends DynamodbItem> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Class<T> typeParameterClass;
    private final ConfigService configService;
    private final DynamoDbTable<T> table;
    private final DynamoDbEnhancedClient client;

    public DataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient client,
            ConfigService configService) {
        this.typeParameterClass = typeParameterClass;
        this.configService = configService;
        this.table = client.table(tableName, TableSchema.fromBean(this.typeParameterClass));
        this.client = client;
    }

    @ExcludeFromGeneratedCoverageReport
    public static DynamoDbEnhancedClient getClient() {
        var client = DynamoDbClient.builder().httpClient(UrlConnectionHttpClient.create()).build();

        return DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
    }

    public void create(T item, ConfigurationVariable tableTtl) {
        item.setTtl(
                Instant.now()
                        .plusSeconds(Long.parseLong(configService.getSsmParameter(tableTtl)))
                        .getEpochSecond());
        create(item);
    }

    public void create(T item) {
        table.putItem(item);
    }

    public void createIfNotExists(T item) {
        PutItemEnhancedRequest<T> enhancedRequest =
                PutItemEnhancedRequest.builder(typeParameterClass)
                        .item(item)
                        .conditionExpression(
                                Expression.builder()
                                        .expression("attribute_not_exists(userId)")
                                        .build())
                        .build();

        table.putItem(enhancedRequest);
    }

    public T getItem(String partitionValue, String sortValue) {
        var key = Key.builder().partitionValue(partitionValue).sortValue(sortValue).build();
        return getItemByKey(key, true);
    }

    public T getItem(String partitionValue) {
        return getItem(partitionValue, true);
    }

    public T getItem(String partitionValue, boolean warnOnNull) {
        var key = Key.builder().partitionValue(partitionValue).build();
        return getItemByKey(key, warnOnNull);
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
                        .toList();

        if (Objects.isNull(results) || results.isEmpty()) {
            return null;
        }
        return results.get(0);
    }

    public List<T> getItems(String partitionValue) {
        var key = Key.builder().partitionValue(partitionValue).build();
        return table.query(QueryConditional.keyEqualTo(key)).stream()
                .flatMap(page -> page.items().stream())
                .toList();
    }

    public List<T> getItemsWithBooleanAttribute(String partitionValue, String name, boolean value) {
        var queryConditional =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(partitionValue).build());
        var filterExpression =
                Expression.builder()
                        .expression("#a = :b")
                        .putExpressionName("#a", name)
                        .putExpressionValue(":b", AttributeValue.builder().bool(value).build())
                        .build();
        var queryEnhancedRequest =
                QueryEnhancedRequest.builder()
                        .queryConditional(queryConditional)
                        .filterExpression(filterExpression)
                        .build();
        return table.query(queryEnhancedRequest).stream()
                .flatMap(page -> page.items().stream())
                .toList();
    }

    public List<T> getItemsBySortKeyPrefix(String partitionValue, String sortPrefix) {
        Key key = Key.builder().partitionValue(partitionValue).sortValue(sortPrefix).build();

        return table.query(QueryConditional.sortBeginsWith(key)).stream()
                .flatMap(page -> page.items().stream())
                .toList();
    }

    public T update(T item) {
        return table.updateItem(item);
    }

    public T delete(String partitionValue, String sortValue) {
        var key = Key.builder().partitionValue(partitionValue).sortValue(sortValue).build();
        return table.deleteItem(key);
    }

    public List<T> delete(List<T> items) {
        return items.stream().map(table::deleteItem).toList();
    }

    public void deleteAllByPartition(String partitionValue) throws DataStoreException {
        var itemsToDelete = getItems(partitionValue);
        if (itemsToDelete.isEmpty()) {
            return;
        }
        var writeBatchBuilder = WriteBatch.builder(typeParameterClass).mappedTableResource(table);
        itemsToDelete.forEach(writeBatchBuilder::addDeleteItem);
        var batchWriteResult =
                client.batchWriteItem(b -> b.writeBatches(writeBatchBuilder.build()));

        if (!batchWriteResult.unprocessedDeleteItemsForTable(table).isEmpty()) {
            var joiner = new StringJoiner(", ");
            batchWriteResult
                    .unprocessedDeleteItemsForTable(table)
                    .forEach(key -> joiner.add(stringifyKey(key)));
            throw new DataStoreException(
                    String.format("Unable to delete datastore items: %s", joiner));
        }
    }

    private T getItemByKey(Key key, boolean warnOnNull) {
        T result = table.getItem(key);
        if (warnOnNull && result == null) {
            var message =
                    new StringMapMessage()
                            .with("datastore", "Null result retrieved from DynamoDB")
                            .with("table", table.describeTable().table().tableName());
            LOGGER.warn(message);
        }
        return result;
    }

    private String stringifyKey(Key key) {
        return String.format(
                "partition key: '%s', sort key: '%s'",
                key.partitionKeyValue(), key.sortKeyValue().map(Object::toString).orElse("none"));
    }
}
