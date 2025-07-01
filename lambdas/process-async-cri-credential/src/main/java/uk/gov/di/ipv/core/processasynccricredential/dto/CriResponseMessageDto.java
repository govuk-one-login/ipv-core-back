package uk.gov.di.ipv.core.processasynccricredential.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CriResponseMessageDto {

    @JsonProperty("sub")
    private String userId;

    @JsonProperty("state")
    private String oauthState;

    @JsonProperty("govuk_signin_journey_id")
    private String journeyId;

    @JsonProperty("https://vocab.account.gov.uk/v1/credentialJWT")
    private List<String> verifiableCredentialJWTs;

    private String error;

    @JsonProperty("error_description")
    private String errorDescription;
}
