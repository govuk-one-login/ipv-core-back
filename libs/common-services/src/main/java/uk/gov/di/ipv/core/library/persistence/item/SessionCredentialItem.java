package uk.gov.di.ipv.core.library.persistence.item;

import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbIgnore;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
@NoArgsConstructor
public class SessionCredentialItem implements DynamodbItem {

    private static final String SORT_KEY_TEMPLATE = "%s#%s";
    public static final String SORT_KEY_DELIMITER = "#";
    private String ipvSessionId;
    private String sortKey;
    private String credential;
    private boolean receivedThisSession;
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

    @DynamoDbIgnore
    public String getCriId() {
        return sortKey.split(SORT_KEY_DELIMITER)[0];
    }

    @Override
    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
