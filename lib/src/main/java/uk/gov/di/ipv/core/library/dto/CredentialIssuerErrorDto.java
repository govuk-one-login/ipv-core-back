package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@AllArgsConstructor
public class CredentialIssuerErrorDto {
    @JsonProperty("error")
    private final String error;

    @JsonProperty(value = "error_description")
    private final String errorDescription;

    @JsonProperty(value = "state")
    private final String state;

    @JsonProperty(value = "credential_issuer_id")
    private final String credentialIssuerId;

    @JsonProperty(value = "ipv_session_id")
    private final String ipvSessionId;

    @JsonProperty(value = "redirect_uri")
    private final String redirectUri;
}
