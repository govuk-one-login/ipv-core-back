package uk.gov.di.ipv.core.library.dto;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ClientSessionDetailsDto {
    String reseponseType;
    String clientId;
    String redirectUri;
    String scope;
    String state;

    public ClientSessionDetailsDto(
            String reseponseType, String clientId, String redirectUri, String scope, String state) {
        this.reseponseType = reseponseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
    }

    public String getReseponseType() {
        return reseponseType;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getState() {
        return state;
    }
}
