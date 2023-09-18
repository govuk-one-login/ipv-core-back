package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@AllArgsConstructor
@NoArgsConstructor
@Data
public class AuthorizationCodeItem implements DynamodbItem {

    private String authCode;
    private String ipvSessionId;
    private String redirectUrl;
    private String issuedAccessToken;
    private String exchangeDateTime;
    private String creationDateTime;
    private long ttl;

    @DynamoDbPartitionKey
    public String getAuthCode() {
        return authCode;
    }
}
