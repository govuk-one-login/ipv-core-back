package uk.gov.di.ipv.core.buildcrioauthrequest.domain;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

public class CachedOAuthCriEncryptionKeyTest {
    private Integer convertMinutesToMilliseconds(Integer minutes) {
        return minutes * 60 * 1000;
    }

    @Test
    void isExpiredShouldReturnFalseIfCreatedDateIsWithinCachedDuration() throws Exception {
        var cachedKey =
                new CachedOAuthCriEncryptionKey(
                        RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK),
                        new Date(new Date().getTime() - convertMinutesToMilliseconds(2)));

        assertFalse(cachedKey.isExpired(5));
    }

    @Test
    void isExpiredShouldReturnTrueIfCreatedDateIsOutsideCachedDuration() throws Exception {
        var cachedKey =
                new CachedOAuthCriEncryptionKey(
                        RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK),
                        new Date(new Date().getTime() - convertMinutesToMilliseconds(10)));

        assertTrue(cachedKey.isExpired(5));
    }
}
