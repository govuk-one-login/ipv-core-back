package uk.gov.di.ipv.core.library.persistence.item;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.NoCurrentStateException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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
    private Vot vot;
    private long ttl;
    private IpvJourneyTypes journeyType;
    private String emailAddress;
    private ReverificationStatus reverificationStatus;
    private List<String> stateStack = new ArrayList<>();

    // Only for passing the featureSet to the external API lambdas at the end of the user journey.
    // Not for general use.
    private String featureSet;
    private boolean inheritedIdentityReceivedThisSession;
    private String riskAssessmentCredential;

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

    public List<String> getFeatureSetAsList() {
        return (featureSet != null)
                ? Arrays.asList(featureSet.split(","))
                : Collections.emptyList();
    }

    public void setFeatureSetFromList(List<String> featureSet) {
        this.featureSet =
                (featureSet != null && !featureSet.isEmpty()) ? String.join(",", featureSet) : null;
    }

    public void pushState(IpvJourneyTypes journeyType, String state) {
        stateStack.add(String.format("%s/%s", journeyType.name(), state));
    }

    public void pushState(String state) throws NoCurrentStateException {
        if (this.stateStack.isEmpty()) {
            throw new NoCurrentStateException();
        }
        var currentJourney =
                IpvJourneyTypes.valueOf(stateStack.get(stateStack.size() - 1).split("/", 2)[0]);
        pushState(currentJourney, state);
    }
}
