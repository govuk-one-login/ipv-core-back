package uk.gov.di.ipv.core.library.dto;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
public class AuthorizationCodeMetadata {
    private String redirectUrl;
    private String creationDateTime;
    private String exchangeDateTime;

    public AuthorizationCodeMetadata() {}

    public AuthorizationCodeMetadata(
            String redirectUrl, String creationDateTime, String exchangeDateTime) {
        this.redirectUrl = redirectUrl;
        this.creationDateTime = creationDateTime;
        this.exchangeDateTime = exchangeDateTime;
    }
}
