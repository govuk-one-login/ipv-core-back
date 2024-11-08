package uk.gov.di.ipv.core.library.oauthkeyservice.domain;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CachedJWKSetTest {

    @Test
    void isExpiredShouldReturnTrue() {
        assertTrue(new CachedJWKSet(new JWKSet(), Instant.now().minusSeconds(10)).isExpired());
    }

    @Test
    void isExpiredShouldReturnFalse() {
        assertFalse(new CachedJWKSet(new JWKSet(), Instant.now().plusSeconds(10)).isExpired());
    }
}
