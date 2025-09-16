package uk.gov.di.ipv.core.library.persistence;

import org.apache.commons.collections4.ListUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteResult;
import software.amazon.awssdk.enhanced.dynamodb.model.PutItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.exceptions.BatchProcessingException;
import uk.gov.di.ipv.core.library.exceptions.ItemAlreadyExistsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.List;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;

public class DynamoDataStore<T extends PersistenceItem> implements DataStore<T> {

    private static final Logger LOGGER = LogManager.getLogger();
    public static final int MAX_ITEMS_IN_WRITE_BATCH = 25;
    private final Class<T> typeParameterClass;
    private final ConfigService configService;

    private final DynamoDbTable<T> table;

    public DynamoDataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient client,
            ConfigService configService) {
        this.typeParameterClass = typeParameterClass;
        this.configService = configService;
        this.table = client.table(tableName, TableSchema.fromBean(this.typeParameterClass));
    }

    @ExcludeFromGeneratedCoverageReport
    public static DynamoDbEnhancedClient getClient() {
        var client =
                DynamoDbClient.builder()
                        .region(EU_WEST_2)
                        .httpClient(AwsCrtHttpClient.create())
                        .build();

        return DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
    }

    @ExcludeFromGeneratedCoverageReport
    public DynamoDbTable<T> getTable() {
        return table;
    }

    @Override
    public void create(T item, long ttlSeconds) {
        item.setTtl(Instant.now().plusSeconds(ttlSeconds).getEpochSecond());
        create(item);
    }

    @Override
    public void create(T item) {
        table.putItem(item);
    }

    @Override
    public void createIfNotExists(T item) throws ItemAlreadyExistsException {
        try {
            PutItemEnhancedRequest<T> enhancedRequest =
                    PutItemEnhancedRequest.builder(typeParameterClass)
                            .item(item)
                            .conditionExpression(
                                    Expression.builder()
                                            .expression("attribute_not_exists(userId)")
                                            .build())
                            .build();

            table.putItem(enhancedRequest);
        } catch (ConditionalCheckFailedException e) {
            throw new ItemAlreadyExistsException(e);
        }
    }

    @ExcludeFromGeneratedCoverageReport
    @Override
    public void createOrUpdate(List<T> items) throws BatchProcessingException {
        processBatchOperation(items, false);
    }

    @Override
    public T getItem(String partitionValue, String sortValue) {
        var key = Key.builder().partitionValue(partitionValue).sortValue(sortValue).build();
        return getItemByKey(key);
    }

    @Override
    public T getItem(String partitionValue) {
        var key = Key.builder().partitionValue(partitionValue).build();
        return getItemByKey(key);
    }

    @Override
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

        if (results.isEmpty()) {
            return null;
        }
        return results.get(0);
    }

    @Override
    public List<T> getItems(String partitionValue) {
        var key = Key.builder().partitionValue(partitionValue).build();
        return table.query(QueryConditional.keyEqualTo(key)).stream()
                .flatMap(page -> page.items().stream())
                .toList();
    }

    @Override
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

    @Override
    public List<T> getItemsBySortKeyPrefix(String partitionValue, String sortPrefix) {
        Key key = Key.builder().partitionValue(partitionValue).sortValue(sortPrefix).build();

        return table.query(QueryConditional.sortBeginsWith(key)).stream()
                .flatMap(page -> page.items().stream())
                .toList();
    }

    @Override
    public T update(T item) {
        return table.updateItem(item);
    }

    @Override
    public T delete(String partitionValue, String sortValue) {
        var key = Key.builder().partitionValue(partitionValue).sortValue(sortValue).build();
        return table.deleteItem(key);
    }

    @Override
    @ExcludeFromGeneratedCoverageReport
    public void delete(List<T> items) throws BatchProcessingException {
        processBatchOperation(items, true);
    }

    @Override
    public void deleteAllByPartition(String partitionValue) throws BatchProcessingException {
        delete(getItems(partitionValue));
    }

    @ExcludeFromGeneratedCoverageReport
    private void processBatchOperation(List<T> items, boolean isForDeletion)
            throws BatchProcessingException {
        for (List<T> subItems : ListUtils.partition(items, MAX_ITEMS_IN_WRITE_BATCH)) {
            if (!subItems.isEmpty()) {
                BatchWriteResult batchWriteResult =
                        processBatchWrite(
                                isForDeletion
                                        ? createWriteBatchForDeleteItems(subItems)
                                        : createWriteBatchForPutItems(subItems));
                // 'unprocessedDeleteItemsForTable()' returns keys for delete requests that did not
                // process.
                List<Key> unprocessedItems =
                        batchWriteResult.unprocessedDeleteItemsForTable(this.table);
                if (!unprocessedItems.isEmpty()) {
                    String errMessage = "Failed during batch deletion.";
                    LOGGER.error(LogHelper.buildLogMessage(errMessage));
                    throw new BatchProcessingException(errMessage);
                }
            } else {
                LOGGER.info(LogHelper.buildLogMessage("No items to delete"));
            }
        }
    }

    @ExcludeFromGeneratedCoverageReport
    private WriteBatch createWriteBatchForPutItems(List<T> items) {
        WriteBatch.Builder<T> builder =
                WriteBatch.builder(this.typeParameterClass).mappedTableResource(this.table);
        for (T item : items) {
            builder.addPutItem(item).build();
        }
        return builder.build();
    }

    @ExcludeFromGeneratedCoverageReport
    private WriteBatch createWriteBatchForDeleteItems(List<T> items) {
        WriteBatch.Builder<T> builder =
                WriteBatch.builder(this.typeParameterClass).mappedTableResource(this.table);
        for (T item : items) {
            builder.addDeleteItem(item).build();
        }
        return builder.build();
    }

    @ExcludeFromGeneratedCoverageReport
    private BatchWriteResult processBatchWrite(WriteBatch writeBatch) {
        return getClient()
                .batchWriteItem(
                        BatchWriteItemEnhancedRequest.builder().writeBatches(writeBatch).build());
    }

    private T getItemByKey(Key key) {
        return table.getItem(key);
    }
}
