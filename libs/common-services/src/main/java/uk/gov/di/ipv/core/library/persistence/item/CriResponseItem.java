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
import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CriResponseItem implements PersistenceItem {
    private String userId;
    private String credentialIssuer;
    private String issuerResponse;
    private String oauthState;
    private Instant dateCreated;
    private String status;
    private long ttl;
    private List<String> featureSet;
    private boolean reproveIdentity;

    @DynamoDbPartitionKey
    public String getUserId() {
        return userId;
    }

    @DynamoDbSortKey
    public String getCredentialIssuer() {
        return credentialIssuer;
    }
}
