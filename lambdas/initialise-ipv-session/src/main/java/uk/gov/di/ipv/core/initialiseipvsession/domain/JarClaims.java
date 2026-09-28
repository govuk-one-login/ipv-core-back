package uk.gov.di.ipv.core.initialiseipvsession.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record JarClaims(
        @JsonProperty(value = "update_identity") Boolean updateIdentity, JarUserInfo userinfo) {}
