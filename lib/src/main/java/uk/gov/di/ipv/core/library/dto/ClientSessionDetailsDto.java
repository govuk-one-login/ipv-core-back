package uk.gov.di.ipv.core.library.dto;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
public class ClientSessionDetailsDto {
    private String responseType;
    private String clientId;
    private String redirectUri;
    private String state;
    private String userId;
    private boolean debugJourney;

    public ClientSessionDetailsDto() {}

    public ClientSessionDetailsDto(
            String responseType,
            String clientId,
            String redirectUri,
            String state,
            String userId,
            boolean debugJourney) {
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.userId = userId;
        this.debugJourney = debugJourney;
    }
}
