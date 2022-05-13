package uk.gov.di.ipv.core.library.dto;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class ClientSessionDetailsDto {
    String responseType;
    String clientId;
    String redirectUri;
    String state;
    boolean isDebugJourney;

    public ClientSessionDetailsDto() {}

    public ClientSessionDetailsDto(
            String responseType,
            String clientId,
            String redirectUri,
            String state,
            boolean isDebugJourney) {
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.isDebugJourney = isDebugJourney;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public boolean getIsDebugJourney() {
        return isDebugJourney;
    }

    public void setIsDebugJourney(boolean isDebugJourney) {
        this.isDebugJourney = isDebugJourney;
    }
}
