package uk.gov.di.ipv.core.library.persistence.item;

import com.nimbusds.jwt.SignedJWT;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class SessionCredentialItem implements DynamodbItem {

    private static final String SORT_KEY_TEMPLATE = "%s#%s";
    private final String ipvSessionId;
    private final String sortKey;
    private final String credential;
    private final boolean receivedThisSession;
    private long ttl;

    public SessionCredentialItem(
            String ipvSessionId,
            String criId,
            SignedJWT signedCredJwt,
            boolean receivedThisSession) {
        this.ipvSessionId = ipvSessionId;
        this.sortKey = String.format(SORT_KEY_TEMPLATE, criId, signedCredJwt.getSignature());
        this.credential = signedCredJwt.serialize();
        this.receivedThisSession = receivedThisSession;
    }

    @DynamoDbPartitionKey
    public String getIpvSessionId() {
        return ipvSessionId;
    }

    @DynamoDbSortKey
    public String getSortKey() {
        return sortKey;
    }

    @Override
    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
