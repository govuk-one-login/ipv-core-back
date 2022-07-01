package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeServiceTest {

    @Mock private DataStore<AuthorizationCodeItem> mockDataStore;
    @Mock private ConfigurationService mockConfigurationService;

    private AuthorizationCodeService authorizationCodeService;

    @BeforeEach
    void setUp() {
        authorizationCodeService =
                new AuthorizationCodeService(mockDataStore, mockConfigurationService);
    }

    @Test
    void shouldReturnAnAuthorisationCode() {
        AuthorizationCode result = authorizationCodeService.generateAuthorizationCode();

        assertNotNull(result);
    }

    @Test
    void shouldCreateAuthorizationCodeInDataStore() {
        AuthorizationCode testCode = new AuthorizationCode();
        String ipvSessionId = "session-12345";
        String redirectUrl = "https://example.com/callback";
        authorizationCodeService.persistAuthorizationCode(
                testCode.getValue(), ipvSessionId, redirectUrl);

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(AuthorizationCodeItem.class);
        verify(mockDataStore).create(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(
                ipvSessionId, authorizationCodeItemArgumentCaptor.getValue().getIpvSessionId());
        assertEquals(
                DigestUtils.sha256Hex(testCode.getValue()),
                authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(redirectUrl, authorizationCodeItemArgumentCaptor.getValue().getRedirectUrl());
    }

    @Test
    void shouldGetSessionIdByAuthCodeWhenValidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();
        String ipvSessionId = "session-12345";

        AuthorizationCodeItem testItem = new AuthorizationCodeItem();
        testItem.setIpvSessionId(ipvSessionId);

        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue())))
                .thenReturn(testItem);

        AuthorizationCodeItem authorizationCodeItem =
                authorizationCodeService.getAuthorizationCodeItem(testCode.getValue()).get();

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertEquals(ipvSessionId, authorizationCodeItem.getIpvSessionId());
    }

    @Test
    void shouldReturnEmptyOptionalWhenInvalidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();

        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue()))).thenReturn(null);

        Optional<AuthorizationCodeItem> authorizationCodeItem =
                authorizationCodeService.getAuthorizationCodeItem(testCode.getValue());

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertTrue(authorizationCodeItem.isEmpty());
    }

    @Test
    void shouldCallUpdateWithIssuedAccessTokenValue() {
        AuthorizationCode testCode = new AuthorizationCode();
        AuthorizationCodeItem authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setAuthCode(testCode.getValue());
        authorizationCodeItem.setIpvSessionId("test-session-id");
        authorizationCodeItem.setRedirectUrl("http://example.com");
        authorizationCodeItem.setExchangeDateTime(Instant.now().toString());

        when(mockDataStore.getItem(testCode.getValue())).thenReturn(authorizationCodeItem);
        authorizationCodeService.setIssuedAccessToken(testCode.getValue(), "test-access-token");

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(AuthorizationCodeItem.class);
        verify(mockDataStore).update(authorizationCodeItemArgumentCaptor.capture());

        assertNotNull(authorizationCodeItemArgumentCaptor.getValue().getExchangeDateTime());
    }
}
