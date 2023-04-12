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
    String accessToken;
    String authorizationCode;

    public CredentialIssuerSessionDetailsDto() {}

    public CredentialIssuerSessionDetailsDto(String criId, String state) {
        this.criId = criId;
        this.state = state;
    }

    public CredentialIssuerSessionDetailsDto(String criId, String state, String accessToken) {
        this.criId = criId;
        this.state = state;
        this.accessToken = accessToken;
    }
}
