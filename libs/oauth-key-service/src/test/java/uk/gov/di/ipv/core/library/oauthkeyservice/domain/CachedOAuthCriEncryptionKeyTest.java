package uk.gov.di.ipv.core.library.oauthkeyservice.domain;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.time.LocalDateTime;
import java.time.Month;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

class CachedOAuthCriEncryptionKeyTest {
    private final LocalDateTime MOCK_TODAY_DATE =
            LocalDateTime.of(2024, Month.JANUARY, 10, 12, 5, 0);

    @Test
    void isExpiredShouldReturnFalseIfExpiryDateTimeIsAfterTodayDateTime() throws Exception {
        try (MockedStatic<LocalDateTime> mockedStatic = Mockito.mockStatic(LocalDateTime.class)) {
            mockedStatic.when(LocalDateTime::now).thenReturn(MOCK_TODAY_DATE);

            var cachedKey =
                    new CachedOAuthCriEncryptionKey(
                            RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK),
                            MOCK_TODAY_DATE.plusMinutes(10));

            assertFalse(cachedKey.isExpired());
        }
    }

    @Test
    void isExpiredShouldReturnTrueIfExpiryDateTimeIsBeforeTodayDateTime() throws Exception {
        try (MockedStatic<LocalDateTime> mockedStatic = Mockito.mockStatic(LocalDateTime.class)) {
            mockedStatic.when(LocalDateTime::now).thenReturn(MOCK_TODAY_DATE);

            var cachedKey =
                    new CachedOAuthCriEncryptionKey(
                            RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK),
                            MOCK_TODAY_DATE.minusMinutes(10));

            assertTrue(cachedKey.isExpired());
        }
    }
}
