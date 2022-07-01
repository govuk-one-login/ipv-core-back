package uk.gov.di.ipv.core.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class AccessTokenItem implements DynamodbItem {
    private String accessToken;
    private String ipvSessionId;
    private String revokedAtDateTime;
    private long ttl;

    @DynamoDbPartitionKey
    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getIpvSessionId() {
        return ipvSessionId;
    }

    public void setIpvSessionId(String ipvSessionId) {
        this.ipvSessionId = ipvSessionId;
    }

    public String getRevokedAtDateTime() {
        return revokedAtDateTime;
    }

    public void setRevokedAtDateTime(String revokedAtDateTime) {
        this.revokedAtDateTime = revokedAtDateTime;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
