package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class RetrieveCriRequestDto {

    private final String accessToken;

    private final String credentialIssuerId;

    private final String ipvSessionId;

    public RetrieveCriRequestDto(
            @JsonProperty(value = "access_token") String accessToken,
            @JsonProperty(value = "credential_issuer_id") String credentialIssuerId,
            @JsonProperty(value = "ipv_session_id") String ipvSessionId) {
        this.accessToken = accessToken;
        this.credentialIssuerId = credentialIssuerId;
        this.ipvSessionId = ipvSessionId;
    }
}
