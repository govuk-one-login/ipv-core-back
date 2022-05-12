package uk.gov.di.ipv.core.library.dto;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class CredentialIssuerSessionDetailsDto {
    String criId;

    String state;

    public CredentialIssuerSessionDetailsDto() {}

    public CredentialIssuerSessionDetailsDto(String criId, String state) {
        this.criId = criId;
        this.state = state;
    }

    public String getCriId() {
        return criId;
    }

    public void setCriId(String criId) {
        this.criId = criId;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }
}
