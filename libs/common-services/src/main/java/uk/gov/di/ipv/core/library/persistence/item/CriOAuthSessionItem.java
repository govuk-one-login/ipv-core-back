package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CriOAuthSessionItem implements DynamodbItem {
    private String criOAuthSessionId;
    private String clientOAuthSessionId;
    private String criId;
    private String accessToken;
    private String authorizationCode;
    private long ttl;

    @DynamoDbPartitionKey
    public String getCriOAuthSessionId() {
        return criOAuthSessionId;
    }
}
