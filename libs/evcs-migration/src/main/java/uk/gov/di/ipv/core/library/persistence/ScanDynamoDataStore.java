package uk.gov.di.ipv.core.library.persistence;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static java.util.Objects.requireNonNullElse;

public class ScanDynamoDataStore<T extends PersistenceItem> extends DynamoDataStore<T> {

    private static final Logger LOGGER = LogManager.getLogger();
    public static final int DEFAULT_PAGE_SIZE = 100;

    @ExcludeFromGeneratedCoverageReport
    public ScanDynamoDataStore(
            String tableName,
            Class<T> typeParameterClass,
            DynamoDbEnhancedClient client,
            ConfigService configService) {
        super(tableName, typeParameterClass, client, configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public PageIterable<T> scan(
            Map<String, AttributeValue> exclusiveStartKey,
            Integer pageSize,
            String... attributesToProject) {
        LOGGER.info(
                LogHelper.buildLogMessage(
                        String.format(
                                "Scanning table with exclusiveStartKey as [%s]",
                                exclusiveStartKey)));
        ScanEnhancedRequest.Builder builder =
                ScanEnhancedRequest.builder()
                        .limit(requireNonNullElse(pageSize, DEFAULT_PAGE_SIZE))
                        .exclusiveStartKey(exclusiveStartKey);

        if (attributesToProject != null) {
            for (String attr : attributesToProject) {
                builder.addAttributeToProject(attr);
            }
        }

        return getTable().scan(builder.build());
    }
}
