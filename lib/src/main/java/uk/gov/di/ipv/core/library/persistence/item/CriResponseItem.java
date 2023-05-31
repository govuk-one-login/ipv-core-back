package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.Instant;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CriResponseItem implements DynamodbItem {
    private String userId;
    private String credentialIssuer;
    private String credential;
    private Instant dateCreated;
    private Instant expirationTime;
    private long ttl;

    @DynamoDbPartitionKey
    public String getUserId() {
        return userId;
    }

    @DynamoDbSortKey
    public String getCredentialIssuer() {
        return credentialIssuer;
    }
}
