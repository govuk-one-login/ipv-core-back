package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeServiceTest {
    @Mock private ConfigurationService mockConfigurationService;

    private AuthorizationCodeService authorizationCodeService;

    @BeforeEach
    void setUp() {
        authorizationCodeService = new AuthorizationCodeService(mockConfigurationService);
    }

    @Test
    void shouldReturnAnAuthorisationCode() {
        AuthorizationCode result = authorizationCodeService.generateAuthorizationCode();

        assertNotNull(result);
    }

    @Test
    void isExpiredReturnsTrueIfAuthCodeItemHasExpired() {
        when(mockConfigurationService.getSsmParameter(any())).thenReturn("600");
        AuthorizationCodeMetadata expiredAuthCodeMetadata =
                new AuthorizationCodeMetadata(
                        "redirect-url", Instant.now().minusSeconds(601).toString());

        assertTrue(authorizationCodeService.isExpired(expiredAuthCodeMetadata));
    }

    @Test
    void isExpiredReturnsFalseIfAuthCodeItemHasNotExpired() {
        when(mockConfigurationService.getSsmParameter(any())).thenReturn("600");
        AuthorizationCodeMetadata expiredAuthCodeMetadata =
                new AuthorizationCodeMetadata(
                        "redirect-url", Instant.now().minusSeconds(599).toString());

        assertFalse(authorizationCodeService.isExpired(expiredAuthCodeMetadata));
    }
}
