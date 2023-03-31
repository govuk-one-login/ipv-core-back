package uk.gov.di.ipv.core.library.persistence.item;

import lombok.Builder;
import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@Builder
public class CriOAuthSessionItem implements DynamodbItem {
    private String criOAuthSessionId;
    private String criId;
    private String accessToken;
    private String authorizationCode;
    private String userId;
    private String govukSigninJourneyId;
    private long ttl;
    private String creationDateTime;
    private IpvJourneyTypes journeyType;

    @DynamoDbPartitionKey
    public String getCriOAuthSessionId() {
        return criOAuthSessionId;
    }
}
