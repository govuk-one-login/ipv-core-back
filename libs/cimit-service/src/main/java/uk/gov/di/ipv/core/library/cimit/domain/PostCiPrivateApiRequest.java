package uk.gov.di.ipv.core.library.cimit.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PostCiPrivateApiRequest(@JsonProperty("signed_jwt") String signedJwt) {}
