package uk.gov.di.ipv.core.library.dto;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
public class AccessTokenMetadata {
    private String creationDateTime;
    private String expiryDateTime;
    private String revokedAtDateTime;

    public AccessTokenMetadata() {}

    public AccessTokenMetadata(
            String creationDateTime, String expiryDateTime, String revokedAtDateTime) {
        this.creationDateTime = creationDateTime;
        this.expiryDateTime = expiryDateTime;
        this.revokedAtDateTime = revokedAtDateTime;
    }
}
