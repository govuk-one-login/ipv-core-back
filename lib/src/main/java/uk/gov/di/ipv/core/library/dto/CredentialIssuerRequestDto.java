package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Optional;

@ExcludeFromGeneratedCoverageReport
@Getter
public class CredentialIssuerRequestDto {

    private final String authorizationCode;

    private final String credentialIssuerId;

    private final String ipvSessionId;

    private final String redirectUri;

    private final String state;

    private final Optional<String> error;

    private final Optional<String> errorDescription;

    public CredentialIssuerRequestDto(
            @JsonProperty(value = "authorization_code") String authorizationCode,
            @JsonProperty(value = "credential_issuer_id") String credentialIssuerId,
            @JsonProperty(value = "ipv_session_id") String ipvSessionId,
            @JsonProperty(value = "redirect_uri") String redirectUri,
            @JsonProperty(value = "state") String state,
            @JsonProperty(value = "error") String error,
            @JsonProperty(value = "error_description") String errorDescription) {
        this.authorizationCode = authorizationCode;
        this.credentialIssuerId = credentialIssuerId;
        this.ipvSessionId = ipvSessionId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.error = Optional.ofNullable(error);
        this.errorDescription = Optional.ofNullable(errorDescription);
    }
}
