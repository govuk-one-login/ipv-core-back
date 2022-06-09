package uk.gov.di.ipv.core.library.dto;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
public class CredentialIssuerSessionDetailsDto {
    String criId;

    String state;

    public CredentialIssuerSessionDetailsDto() {}

    public CredentialIssuerSessionDetailsDto(String criId, String state) {
        this.criId = criId;
        this.state = state;
    }
}
