package uk.gov.di.ipv.core.library.persistence.item;

import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbIgnore;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;

import java.time.Instant;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
@NoArgsConstructor
public class SessionCredentialItem implements PersistenceItem {

    private static final String SORT_KEY_TEMPLATE = "%s#%s";
    public static final String SORT_KEY_DELIMITER = "#";
    private String ipvSessionId;
    private String sortKey;
    private String credential;
    private boolean receivedThisSession;
    private Instant migrated;
    private long ttl;

    public SessionCredentialItem(
            String ipvSessionId,
            Cri cri,
            SignedJWT signedCredJwt,
            boolean receivedThisSession,
            Instant migrated) {
        this.ipvSessionId = ipvSessionId;
        this.sortKey = String.format(SORT_KEY_TEMPLATE, cri.getId(), signedCredJwt.getSignature());
        this.credential = signedCredJwt.serialize();
        this.receivedThisSession = receivedThisSession;
        this.migrated = migrated;
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
