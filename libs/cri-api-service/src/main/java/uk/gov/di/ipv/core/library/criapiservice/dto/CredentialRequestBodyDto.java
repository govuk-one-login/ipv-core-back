package uk.gov.di.ipv.core.library.criapiservice.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class CredentialRequestBodyDto {
    @JsonProperty(value = "sub")
    private String userId;

    @JsonProperty(value = "govuk_signin_journey_id")
    private String journeyId;

    @JsonProperty(value = "client_id")
    private String clientId;

    @JsonProperty(value = "state")
    private String state;
}
