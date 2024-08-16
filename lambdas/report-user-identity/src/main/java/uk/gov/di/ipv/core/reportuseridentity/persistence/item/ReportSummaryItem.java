package uk.gov.di.ipv.core.reportuseridentity.persistence.item;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;
import uk.gov.di.ipv.core.reportuseridentity.persistence.ScanDynamoDataStore;

import java.util.Map;

@DynamoDbBean
@NoArgsConstructor
@AllArgsConstructor
@Data
@ExcludeFromGeneratedCoverageReport
public class ReportSummaryItem implements PersistenceItem {
    String id = ScanDynamoDataStore.KEY_VALUE;

    @JsonProperty("Total P2")
    long totalP2;

    @JsonProperty("Total P2 migrated")
    long totalP2Migrated;

    @JsonProperty("Total P1")
    long totalP1;

    @JsonProperty("Total P0")
    long totalP0;

    @JsonProperty("constituentVcsTotal")
    private Map<String, Long> constituentVcsTotal;

    @DynamoDbPartitionKey
    public String getId() {
        return id;
    }

    @Override
    public void setTtl(long ttl) {
        throw new UnsupportedOperationException("VC store items do not use TTL");
    }
}
