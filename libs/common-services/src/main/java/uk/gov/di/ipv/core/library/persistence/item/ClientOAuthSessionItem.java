package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientOAuthSessionItem implements DynamodbItem {
    private String clientOAuthSessionId;
    private String responseType;
    private String clientId;
    private String redirectUri;
    private String state;
    private String userId;
    private String govukSigninJourneyId;
    private String reproveIdentity;
    private List<String> vtr;
    private long ttl;

    @DynamoDbPartitionKey
    public String getClientOAuthSessionId() {
        return clientOAuthSessionId;
    }
}
