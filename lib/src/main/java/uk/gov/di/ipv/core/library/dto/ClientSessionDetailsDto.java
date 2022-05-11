package uk.gov.di.ipv.core.library.dto;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class ClientSessionDetailsDto {
    String responseType;
    String clientId;
    String redirectUri;
    String scope;
    String state;
    boolean isDebugJourney;
    String request;

    public ClientSessionDetailsDto() {}

    public ClientSessionDetailsDto(
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            boolean isDebugJourney,
            String request) {
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
        this.isDebugJourney = isDebugJourney;
        this.request = request;
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

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
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

    public String getRequest() {
        return request;
    }

    public void setRequest(String request) {
        this.request = request;
    }
}
