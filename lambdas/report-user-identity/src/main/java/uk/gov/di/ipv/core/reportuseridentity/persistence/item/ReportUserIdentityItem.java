package uk.gov.di.ipv.core.reportuseridentity.persistence.item;

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
public class ReportUserIdentityItem {
    public ReportUserIdentityItem(
            String userId,
            String identity,
            int vcCount,
            List<String> constituentVcs,
            Boolean migrated) {
        this.hashUserId = DigestUtils.sha256Hex(userId);
        this.userId = userId;
        this.identity = identity;
        this.vcCount = vcCount;
        this.constituentVcs = constituentVcs;
        this.migrated = migrated;
    }

    private String hashUserId;
    private String userId;
    private String identity;
    private int vcCount;
    private List<String> constituentVcs;
    private Boolean migrated;

    @DynamoDbPartitionKey
    public String getHashUserId() {
        return hashUserId;
    }
}
