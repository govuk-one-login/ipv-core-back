package uk.gov.di.ipv.core.library.persistence.item;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;

import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
public class IpvSessionItem implements DynamodbItem {
    private String ipvSessionId;
    private String clientOAuthSessionId;
    private String criOAuthSessionId;
    private String userState;
    private String creationDateTime;
    private String authorizationCode;
    private AuthorizationCodeMetadata authorizationCodeMetadata;
    private String accessToken;
    private AccessTokenMetadata accessTokenMetadata;
    private String errorCode;
    private String errorDescription;
    private String vot;
    private long ttl;
    private IpvJourneyTypes journeyType;
    private List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetails;
    private String emailAddress;
    // Only for passing the featureSet to the external API lambdas at the end of the user journey.
    // Not for general use.
    private String featureSet;
    private List<String> vcReceivedThisSession;

    @DynamoDbPartitionKey
    public String getIpvSessionId() {
        return ipvSessionId;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "authorizationCode")
    public String getAuthorizationCode() {
        return authorizationCode;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "accessToken")
    public String getAccessToken() {
        return accessToken;
    }
}
