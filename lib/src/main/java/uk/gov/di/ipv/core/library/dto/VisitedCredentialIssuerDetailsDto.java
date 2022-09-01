package uk.gov.di.ipv.core.library.dto;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
public class VisitedCredentialIssuerDetailsDto {
    private String criId;
    private boolean returnedWithVc;
    private String oauthError;

    public VisitedCredentialIssuerDetailsDto() {}

    public VisitedCredentialIssuerDetailsDto(
            String criId, boolean returnedWithVc, String oauthError) {
        this.criId = criId;
        this.returnedWithVc = returnedWithVc;
        this.oauthError = oauthError;
    }
}
