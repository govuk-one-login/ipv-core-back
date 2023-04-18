package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

@ExtendWith(MockitoExtension.class)
class CriOAuthSessionServiceTest {
    @Mock private DataStore<CriOAuthSessionItem> mockDataStore;

    @InjectMocks private CriOAuthSessionService criOauthSessionService;

    @Test
    void shouldReturnCriOAuthSessionItem() {
        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .accessToken("testAccessToken")
                        .authorizationCode("testAuthorizationCode")
                        .build();

        when(mockDataStore.getItem(criOAuthSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);

        CriOAuthSessionItem result =
                criOauthSessionService.getCriOauthSessionItem(
                        criOAuthSessionItem.getCriOAuthSessionId());
        ArgumentCaptor<String> criOAuthSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(String.class);

        verify(mockDataStore).getItem(criOAuthSessionItemArgumentCaptor.capture());

        assertEquals(
                criOAuthSessionItem.getCriOAuthSessionId(),
                criOAuthSessionItemArgumentCaptor.getValue());
        assertEquals(criOAuthSessionItem.getCriOAuthSessionId(), result.getCriOAuthSessionId());
        assertEquals(criOAuthSessionItem.getCriId(), result.getCriId());
        assertEquals(criOAuthSessionItem.getAccessToken(), result.getAccessToken());
        assertEquals(criOAuthSessionItem.getAuthorizationCode(), result.getAuthorizationCode());
    }

    @Test
    void shouldCreateCriOAuthSessionItem() {
        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .accessToken("testAccessToken")
                        .authorizationCode("testAuthorizationCode")
                        .build();

        CriOAuthSessionItem result =
                criOauthSessionService.persistCriOAuthSession(
                        criOAuthSessionItem.getCriOAuthSessionId(), criOAuthSessionItem.getCriId(), criOAuthSessionItem.getClientOAuthSessionId());

        ArgumentCaptor<CriOAuthSessionItem> criOAuthSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockDataStore)
                .create(criOAuthSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));

        assertEquals(criOAuthSessionItem.getCriOAuthSessionId(), result.getCriOAuthSessionId());
        assertEquals(criOAuthSessionItem.getCriId(), result.getCriId());
        assertNull(result.getAccessToken());
        assertNull(result.getAuthorizationCode());
    }

    @Test
    void shouldUpdateSessionItem() {
        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .accessToken("testAccessToken")
                        .authorizationCode("testAuthorizationCode")
                        .build();

        criOauthSessionService.updateCriOAuthSessionItem(criOAuthSessionItem);

        verify(mockDataStore).update(criOAuthSessionItem);
    }
}
