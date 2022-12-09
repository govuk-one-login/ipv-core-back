package uk.gov.di.ipv.core.library.persistence.item;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
public class AccessTokenItem implements DynamodbItem {
    private String accessToken;
    private String ipvSessionId;
    private String revokedAtDateTime;
    private long ttl;
    private String expiryDateTime;

    @DynamoDbPartitionKey
    public String getAccessToken() {
        return accessToken;
    }
}
