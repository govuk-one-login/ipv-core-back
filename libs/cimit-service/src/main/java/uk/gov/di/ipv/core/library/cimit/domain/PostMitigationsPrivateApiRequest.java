package uk.gov.di.ipv.core.library.cimit.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record PostMitigationsPrivateApiRequest(
        @JsonProperty("signed_jwts") List<String> signedJwts) {}
