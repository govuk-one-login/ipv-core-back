package uk.gov.di.ipv.core.callticfcri.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.List;

public record TicfCriDto(
        List<String> vtr,
        Vot vot,
        String vtm,
        String sub,
        @JsonProperty("govuk_signin_journey_id") String govukSigninJourneyId,
        @JsonProperty("https://vocab.account.gov.uk/v1/credentialJWT") List<String> credentials) {}
