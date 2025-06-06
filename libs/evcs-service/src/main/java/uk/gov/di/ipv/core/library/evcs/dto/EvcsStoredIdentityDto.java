package uk.gov.di.ipv.core.library.evcs.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.core.library.enums.Vot;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record EvcsStoredIdentityDto(String jwt, Vot vot) {}
