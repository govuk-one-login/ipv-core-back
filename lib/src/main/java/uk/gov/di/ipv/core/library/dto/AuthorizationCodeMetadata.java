package uk.gov.di.ipv.core.library.dto;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.Instant;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
public class AuthorizationCodeMetadata {
    private String redirectUrl;
    private String creationDateTime;

    public AuthorizationCodeMetadata() {}

    public AuthorizationCodeMetadata(String redirectUrl, String creationDateTime) {
        this.redirectUrl = redirectUrl;
        this.creationDateTime = creationDateTime;
    }

    public boolean isExpired(Long expirySeconds) {
        return Instant.parse(creationDateTime).isBefore(Instant.now().minusSeconds(expirySeconds));
    }
}
