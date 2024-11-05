package uk.gov.di.ipv.core.library.oauthkeyservice.domain;

import com.nimbusds.jose.jwk.RSAKey;

import java.time.LocalDateTime;

public record CachedOAuthCriEncryptionKey(RSAKey key, LocalDateTime expiryDate) {
    public boolean isExpired() {
        return expiryDate.isBefore(LocalDateTime.now());
    }
}
