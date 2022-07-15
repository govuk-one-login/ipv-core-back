package uk.gov.di.ipv.core.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class ClientAuthJwtIdItem implements DynamodbItem {
    private String jwtId;
    private String usedAtDateTime;
    private long ttl;

    // required for DynamoDb BeanTableSchema
    public ClientAuthJwtIdItem() {}

    public ClientAuthJwtIdItem(String jwtId, String usedAtDateTime) {
        this.jwtId = jwtId;
        this.usedAtDateTime = usedAtDateTime;
    }

    @DynamoDbPartitionKey
    public String getJwtId() {
        return jwtId;
    }

    public void setJwtId(String jwtId) {
        this.jwtId = jwtId;
    }

    public String getUsedAtDateTime() {
        return usedAtDateTime;
    }

    public void setUsedAtDateTime(String usedAtDateTime) {
        this.usedAtDateTime = usedAtDateTime;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
