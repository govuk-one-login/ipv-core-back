package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.Instant;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationCodeMetadata {
    private String redirectUrl;
    private String creationDateTime;

    public boolean isExpired(Long expirySeconds) {
        return Instant.parse(creationDateTime).isBefore(Instant.now().minusSeconds(expirySeconds));
    }
}
