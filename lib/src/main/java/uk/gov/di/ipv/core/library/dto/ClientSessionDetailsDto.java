package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
public class ClientSessionDetailsDto {
    @JsonProperty String responseType;
    @JsonProperty String clientId;
    @JsonProperty String redirectUri;
    @JsonProperty String scope;
    @JsonProperty String state;

    public ClientSessionDetailsDto() {}

    @JsonCreator
    public ClientSessionDetailsDto(
            @JsonProperty(value = "responseType", required = true) String responseType,
            @JsonProperty(value = "clientId", required = true) String clientId,
            @JsonProperty(value = "redirectUri", required = true) String redirectUri,
            @JsonProperty(value = "scope", required = true) String scope,
            @JsonProperty(value = "state", required = true) String state) {
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
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
}
