package uk.gov.di.ipv.core.library.verifiablecredential.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class VerifiableCredentialResponseDto {
    @JsonProperty(value = "sub")
    private String userId;

    @JsonProperty(value = "https://vocab.account.gov.uk/v1/credentialStatus")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String credentialStatus;

    @JsonProperty(value = "https://vocab.account.gov.uk/v1/credentialJWT")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> verifiableCredentials;
}
