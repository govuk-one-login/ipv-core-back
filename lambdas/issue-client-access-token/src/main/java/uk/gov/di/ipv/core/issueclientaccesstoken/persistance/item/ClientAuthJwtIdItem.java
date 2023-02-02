package uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.item.DynamodbItem;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ClientAuthJwtIdItem implements DynamodbItem {
    private String jwtId;
    private String usedAtDateTime;
    private long ttl;

    public ClientAuthJwtIdItem(String jwtId, String usedAtDateTime) {
        this.jwtId = jwtId;
        this.usedAtDateTime = usedAtDateTime;
    }

    @DynamoDbPartitionKey
    public String getJwtId() {
        return jwtId;
    }
}
