package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;

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
                testCode.getValue(), authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(redirectUrl, authorizationCodeItemArgumentCaptor.getValue().getRedirectUrl());
    }

    @Test
    void shouldGetSessionIdByAuthCodeWhenValidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();
        String ipvSessionId = "session-12345";

        AuthorizationCodeItem testItem = new AuthorizationCodeItem();
        testItem.setIpvSessionId(ipvSessionId);

        when(mockDataStore.getItem(testCode.getValue())).thenReturn(testItem);

        AuthorizationCodeItem authorizationCodeItem =
                authorizationCodeService.getAuthorizationCodeItem(testCode.getValue()).get();

        verify(mockDataStore).getItem(testCode.getValue());
        assertEquals(ipvSessionId, authorizationCodeItem.getIpvSessionId());
    }

    @Test
    void shouldReturnEmptyOptionalWhenInvalidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();

        when(mockDataStore.getItem(testCode.getValue())).thenReturn(null);

        Optional<AuthorizationCodeItem> authorizationCodeItem =
                authorizationCodeService.getAuthorizationCodeItem(testCode.getValue());

        verify(mockDataStore).getItem(testCode.getValue());
        assertTrue(authorizationCodeItem.isEmpty());
    }

    @Test
    void shouldCallDeleteWithAuthCode() {
        AuthorizationCode testCode = new AuthorizationCode();

        authorizationCodeService.revokeAuthorizationCode(testCode.getValue());

        verify(mockDataStore).delete(testCode.getValue());
    }
}
