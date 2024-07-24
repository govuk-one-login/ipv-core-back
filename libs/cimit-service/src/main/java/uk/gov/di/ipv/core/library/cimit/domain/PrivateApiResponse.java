package uk.gov.di.ipv.core.library.cimit.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record PrivateApiResponse(@JsonProperty String result, @JsonProperty String reason) {}
