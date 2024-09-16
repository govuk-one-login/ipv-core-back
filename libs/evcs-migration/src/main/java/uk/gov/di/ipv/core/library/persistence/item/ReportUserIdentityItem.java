package uk.gov.di.ipv.core.library.persistence.item;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@Data
public class ReportUserIdentityItem implements PersistenceItem {
    public ReportUserIdentityItem(
            String userId,
            String identity,
            Integer vcCount,
            List<String> constituentVcs,
            Boolean migrated) {
        this.hashUserId = getUserHash(userId);
        this.userId = userId;
        this.identity = identity;
        this.vcCount = vcCount;
        this.constituentVcs = setConstituentVcsFromList(constituentVcs);
        this.migrated = migrated;
    }

    private String hashUserId;
    @JsonIgnore private String userId;
    private String identity;
    private Integer vcCount;
    private String constituentVcs;
    private Boolean migrated;

    @DynamoDbPartitionKey
    public String getHashUserId() {
        return hashUserId;
    }

    @JsonIgnore
    public String getUserId() {
        return userId;
    }

    @Override
    public void setTtl(long ttl) {
        throw new UnsupportedOperationException("VC store items do not use TTL");
    }

    public static String getUserHash(String userId) {
        return DigestUtils.sha256Hex(userId);
    }

    private String setConstituentVcsFromList(List<String> constituentVcs) {
        return (constituentVcs != null && !constituentVcs.isEmpty())
                ? String.join(",", constituentVcs)
                : null;
    }
}
