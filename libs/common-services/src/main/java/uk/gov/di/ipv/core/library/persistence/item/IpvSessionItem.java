package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.domain.ReverificationFailureCode;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
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
    @Builder.Default private List<String> stateStack = new ArrayList<>();

    // This is a more detailed version of stateStack above and will be used to replace it
    @Builder.Default private List<StateHistoryEntry> stateHistoryStack = new ArrayList<>();

    // These are used as part of an unsuccessful reverification response
    private ReverificationFailureCode failureCode;

    /*
     * journeyContext is used a way of tracking the origin of journeys
     * and can be used to re-route particular contexts
     * @see uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent#TransitionResult
     */
    @Builder.Default private List<String> journeyContexts = new ArrayList<>();

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

    public void pushState(JourneyState newJourneyState, String event) {
        // Record event that moved the user out of the previous state
        if (StringUtils.isNotBlank(event) && !stateHistoryStack.isEmpty()) {
            stateHistoryStack.set(
                    stateHistoryStack.size() - 1,
                    new StateHistoryEntry(stateHistoryStack.getLast().getState(), event));
        }
        // Push the new state with no event
        stateHistoryStack.add(new StateHistoryEntry(newJourneyState.toSessionItemString(), null));
    }

    public void pushState(JourneyState journeyState) {
        stateStack.add(journeyState.toSessionItemString());
    }

    public void popState() {
        stateStack.removeLast();

        // Remove most recent state (which should have null event as the user
        //  hasn't moved off it yet) and reset the last state
        stateHistoryStack.removeLast();
        stateHistoryStack.set(
                stateHistoryStack.size() - 1,
                new StateHistoryEntry(stateHistoryStack.getLast().getState(), null));
    }

    public JourneyState getState() {
        if (stateHistoryStack.isEmpty()) {
            throw new IllegalStateException();
        }
        return new JourneyState(stateHistoryStack.getLast().getState());
    }

    public JourneyState getPreviousState() {
        if (stateHistoryStack.size() < 2) {
            throw new IllegalStateException();
        }
        return new JourneyState(stateHistoryStack.get(stateHistoryStack.size() - 2).getState());
    }

    public void setJourneyContext(String journeyContext) {
        if (!this.journeyContexts.contains(journeyContext)) {
            this.journeyContexts.add(journeyContext);
        }
    }

    public void unsetJourneyContext(String journeyContext) {
        this.journeyContexts.remove(journeyContext);
    }

    public List<String> getActiveJourneyContexts() {
        return this.journeyContexts;
    }
}
