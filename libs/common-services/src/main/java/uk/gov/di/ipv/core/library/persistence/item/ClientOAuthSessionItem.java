package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.Arrays;
import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientOAuthSessionItem implements PersistenceItem {
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
    private long ttl;
    private String evcsAccessToken;

    @DynamoDbPartitionKey
    public String getClientOAuthSessionId() {
        return clientOAuthSessionId;
    }

    public List<String> getScopeClaims() {
        return Arrays.asList(this.scope.split(" "));
    }

    public List<Vot> getRequestedVotsByStrength() {
        return Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH.stream()
                .filter(vot -> vtr.contains(vot.name()))
                .toList();
    }
}
