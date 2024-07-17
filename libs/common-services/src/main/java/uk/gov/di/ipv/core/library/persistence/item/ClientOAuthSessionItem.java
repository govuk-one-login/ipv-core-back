package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Vtr;

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

    // PYIC-6984 can we store the Vtr object directly in dynamo instead of creating it here?
    public Vtr getParsedVtr() {
        return new Vtr(vtr);
    }
}
