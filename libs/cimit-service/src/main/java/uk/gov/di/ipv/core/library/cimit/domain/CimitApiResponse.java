package uk.gov.di.ipv.core.library.cimit.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record CimitApiResponse(String result, String reason, String errorMessage) {}
