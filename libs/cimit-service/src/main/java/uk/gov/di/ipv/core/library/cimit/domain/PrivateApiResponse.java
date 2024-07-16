package uk.gov.di.ipv.core.library.cimit.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PrivateApiResponse(@JsonProperty String result, @JsonProperty String reason) {}
