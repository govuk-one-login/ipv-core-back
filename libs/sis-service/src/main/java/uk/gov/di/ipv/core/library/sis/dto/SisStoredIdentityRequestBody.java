package uk.gov.di.ipv.core.library.sis.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SisStoredIdentityRequestBody(List<Vot> vtr, String govukSigninJourneyId) {}
