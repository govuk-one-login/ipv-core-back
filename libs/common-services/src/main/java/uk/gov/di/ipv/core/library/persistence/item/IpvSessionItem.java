package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.domain.ReverificationFailureCode;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class IpvSessionItem implements PersistenceItem {
    private String ipvSessionId;
    private String clientOAuthSessionId;
    private String criOAuthSessionId;
    private String creationDateTime;
    private String authorizationCode;
    private AuthorizationCodeMetadata authorizationCodeMetadata;
    private String accessToken;
    private AccessTokenMetadata accessTokenMetadata;
    private String errorCode;
    private String errorDescription;
    private Vot vot;
    private long ttl;
    private String emailAddress;
    private ReverificationStatus reverificationStatus;
    private AccountInterventionState initialAccountInterventionState;
    private AisInterventionType aisInterventionType;
    @Builder.Default private List<String> stateStack = new ArrayList<>();

    // These are used as part of an unsuccessful reverification response
    private ReverificationFailureCode failureCode;

    /*
     * journeyContext is used a way of tracking the origin of journeys
     * and can be used to re-route particular contexts
     * @see uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent#TransitionResult
     */
    private String journeyContext;

    // Only for passing the featureSet to the external API lambdas at the end of the user journey.
    // Not for general use.
    private String featureSet;
    private String riskAssessmentCredential;

    private String securityCheckCredential;

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

    @DynamoDbSecondaryPartitionKey(indexNames = "clientOAuthSessionId")
    public String getClientOAuthSessionId() {
        return clientOAuthSessionId;
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

    public void pushState(JourneyState journeyState) {
        stateStack.add(journeyState.toSessionItemString());
    }

    public void popState() {
        stateStack.remove(stateStack.size() - 1);
    }

    public JourneyState getState() {
        if (stateStack.isEmpty()) {
            throw new IllegalStateException();
        }
        return new JourneyState(stateStack.get(stateStack.size() - 1));
    }

    public JourneyState getPreviousState() {
        if (stateStack.size() < 2) {
            throw new IllegalStateException();
        }
        return new JourneyState(stateStack.get(stateStack.size() - 2));
    }
}
