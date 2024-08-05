package uk.gov.di.ipv.core.reportuseridentity.persistence;

import org.apache.commons.collections4.ListUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteResult;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.exceptions.BatchDeleteException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.List;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;

public class DataStore<T> {

    private static final Logger LOGGER = LogManager.getLogger();
    public static final int MAX_ITEMS_IN_WRITE_BATCH = 25;
    private final Class<T> typeParameterClass;
    private final DynamoDbTable<T> table;

    public DataStore(String tableName, Class<T> typeParameterClass, DynamoDbEnhancedClient client) {
        this.typeParameterClass = typeParameterClass;
        this.table = client.table(tableName, TableSchema.fromBean(this.typeParameterClass));
    }

    @ExcludeFromGeneratedCoverageReport
    public static DynamoDbEnhancedClient getClient() {
        var client =
                DynamoDbClient.builder()
                        .region(EU_WEST_2)
                        .httpClient(UrlConnectionHttpClient.create())
                        .build();

        return DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
    }

    @ExcludeFromGeneratedCoverageReport
    public void createOrUpdate(List<T> items) throws BatchDeleteException {
        processBatchOperation(items, false);
    }

    public List<T> getItems() {
        ScanEnhancedRequest scanRequest = ScanEnhancedRequest.builder().build();
        return getTableScan(scanRequest);
    }

    public List<T> getItems(String attrName, String attrValue) {
        var filterExpression =
                Expression.builder()
                        .expression("#a = :b")
                        .putExpressionName("#a", attrName)
                        .putExpressionValue(":b", AttributeValue.builder().s(attrValue).build())
                        .build();
        ScanEnhancedRequest scanRequest =
                ScanEnhancedRequest.builder().filterExpression(filterExpression).build();
        return getTableScan(scanRequest);
    }

    @ExcludeFromGeneratedCoverageReport
    private void processBatchOperation(List<T> items, boolean isForDeletion)
            throws BatchDeleteException {
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
                    throw new BatchDeleteException(errMessage);
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

    private List<T> getTableScan(ScanEnhancedRequest scanRequest) {
        PageIterable<T> pagedResults = table.scan(scanRequest);
        return pagedResults.items().stream().toList();
    }
}
