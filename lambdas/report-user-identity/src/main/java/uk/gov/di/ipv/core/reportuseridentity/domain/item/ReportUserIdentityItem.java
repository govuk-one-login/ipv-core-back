package uk.gov.di.ipv.core.reportuseridentity.domain.item;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.item.PersistenceItem;

import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class ReportUserIdentityItem implements PersistenceItem {
    private String userId;
    private String identity;

    @JsonProperty("constitute")
    private List<String> constituteCriDocumentType;

    private boolean migrated;

    @DynamoDbPartitionKey
    public String getUserId() {
        return userId;
    }

    @Override
    public void setTtl(long ttl) {
        throw new UnsupportedOperationException("TTL not required here");
    }
}
