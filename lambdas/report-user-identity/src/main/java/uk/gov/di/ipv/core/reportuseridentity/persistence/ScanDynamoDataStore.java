package uk.gov.di.ipv.core.reportuseridentity.persistence;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

public class ScanDynamoDataStore<T extends PersistenceItem> extends DynamoDataStore<T> {

    public static final String KEY_VALUE = "1";
    private static final Logger LOGGER = LogManager.getLogger();
    public static final int PAGE_SIZE_LIMIT = 50;

    @ExcludeFromGeneratedCoverageReport
    public ScanDynamoDataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient client,
            ConfigService configService) {
        super(tableName, typeParameterClass, client, configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public PageIterable<T> getScannedItemsPages(
            Map<String, AttributeValue> exclusiveStartKey, String... attributesToProject) {
        return getTableScanResult(exclusiveStartKey, attributesToProject);
    }

    @ExcludeFromGeneratedCoverageReport
    private PageIterable<T> getTableScanResult(
            Map<String, AttributeValue> exclusiveStartKey, String... attributesToProject) {
        LOGGER.info(
                LogHelper.buildLogMessage(
                        String.format(
                                "Scanning table with exclusiveStartKey as [%s]",
                                exclusiveStartKey)));
        ScanEnhancedRequest.Builder builder =
                ScanEnhancedRequest.builder()
                        .limit(PAGE_SIZE_LIMIT)
                        .exclusiveStartKey(exclusiveStartKey);

        if (attributesToProject != null) {
            for (String attr : attributesToProject) {
                builder.addAttributeToProject(attr);
            }
        }

        return getTable().scan(builder.build());
    }
}
