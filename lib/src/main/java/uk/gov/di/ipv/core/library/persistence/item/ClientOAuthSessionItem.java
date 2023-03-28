package uk.gov.di.ipv.core.library.persistence.item;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
public class ClientOAuthSessionItem implements DynamodbItem {
    private String clientOAuthSessionId;
    private String responseType;
    private String clientId;
    private String redirectUri;
    private String state;
    private String userId;
    private String govukSigninJourneyId;
    private long ttl;

    @DynamoDbPartitionKey
    public String getClientOAuthSessionId() {
        return clientOAuthSessionId;
    }
}
