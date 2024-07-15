package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.Arrays;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_BAD_REQUEST;

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
    private String scope;
    private String redirectUri;
    private String state;
    private String userId;
    private String govukSigninJourneyId;
    private Boolean reproveIdentity;
    private List<String> vtr;
    private Vot targetVot;
    private long ttl;
    private String evcsAccessToken;

    public ClientOAuthSessionItem(
            String clientOAuthSessionId,
            String responseType,
            String clientId,
            String scope,
            String redirectUri,
            String state,
            String userId,
            String govukSigninJourneyId,
            Boolean reproveIdentity,
            List<String> vtr,
            String evcsAccessToken,
            Boolean isP1JourneysEnabled)
            throws HttpResponseExceptionWithErrorBody {
        this.clientOAuthSessionId = clientOAuthSessionId;
        this.responseType = responseType;
        this.clientId = clientId;
        this.scope = scope;
        this.redirectUri = redirectUri;
        this.state = state;
        this.userId = userId;
        this.govukSigninJourneyId = govukSigninJourneyId;
        this.reproveIdentity = reproveIdentity;
        this.vtr = vtr;
        this.evcsAccessToken = evcsAccessToken;

        // If we want to prove or mitigate CIs for an identity we want to go for the lowest
        // strength that is acceptable to the caller. We can only prove/mitigate GPG45
        // identities
        this.targetVot = getLowestStrengthRequestedVot(isP1JourneysEnabled);
    }

    @DynamoDbPartitionKey
    public String getClientOAuthSessionId() {
        return clientOAuthSessionId;
    }

    public List<String> getScopeClaims() {
        return Arrays.asList(this.scope.split(" "));
    }

    // Refactor this out in PYIC-6984
    public List<Vot> getRequestedVotsByStrengthDescending() {
        return Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH.stream()
                .filter(vot -> vtr.contains(vot.name()))
                .toList();
    }

    // Refactor this out in PYIC-6984
    public Vot getLowestStrengthRequestedVot(Boolean isP1JourneysEnabled)
            throws HttpResponseExceptionWithErrorBody {
        var requestedVotsByStrengthDescending = getRequestedVotsByStrengthDescending();

        return getWeakestRequestedVotFromVotsByDescendingStrength(
                requestedVotsByStrengthDescending, isP1JourneysEnabled);
    }

    public void updateTargetVotForGpg45Only(Boolean isP1JourneysEnabled)
            throws HttpResponseExceptionWithErrorBody {
        var requestedGpg45VotsByStrengthDescending =
                getRequestedVotsByStrengthDescending().stream()
                        .filter(vot -> vot.getProfileType() == ProfileType.GPG45)
                        .toList();

        this.targetVot =
                getWeakestRequestedVotFromVotsByDescendingStrength(
                        requestedGpg45VotsByStrengthDescending, isP1JourneysEnabled);
    }

    // Refactor this out in PYIC-6984
    private Vot getWeakestRequestedVotFromVotsByDescendingStrength(
            List<Vot> requestedVotsByStrengthDescending, boolean isP1JourneysEnabled)
            throws HttpResponseExceptionWithErrorBody {
        try {
            var lowestStrengthRequestedVot =
                    requestedVotsByStrengthDescending.get(
                            requestedVotsByStrengthDescending.size() - 1);

            if (lowestStrengthRequestedVot == Vot.P1 && !isP1JourneysEnabled) {
                lowestStrengthRequestedVot =
                        requestedVotsByStrengthDescending.get(
                                requestedVotsByStrengthDescending.size() - 2);
            }

            return lowestStrengthRequestedVot;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new HttpResponseExceptionWithErrorBody(SC_BAD_REQUEST, ErrorResponse.INVALID_VTR);
        }
    }
}
