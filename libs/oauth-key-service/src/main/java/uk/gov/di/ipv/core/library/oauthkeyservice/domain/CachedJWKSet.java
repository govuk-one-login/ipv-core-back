package uk.gov.di.ipv.core.library.oauthkeyservice.domain;

import com.nimbusds.jose.jwk.JWKSet;

import java.time.Instant;

public record CachedJWKSet(JWKSet jwkSet, Instant expiry) {
    public boolean isExpired() {
        return expiry.isBefore(Instant.now());
    }
}
