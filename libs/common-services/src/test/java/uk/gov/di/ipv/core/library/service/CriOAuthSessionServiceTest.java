package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.retry.Sleeper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;

@ExtendWith(MockitoExtension.class)
class CriOAuthSessionServiceTest {
    @Mock private DataStore<CriOAuthSessionItem> mockDataStore;
    @Mock private Sleeper mockSleeper;
    @Mock private ConfigService mockConfigService;

    private CriOAuthSessionService criOauthSessionService;

    @BeforeEach
    void setUp() {
        criOauthSessionService = new CriOAuthSessionService(mockDataStore, mockSleeper);
    }

    @Test
    void shouldReturnCriOAuthSessionItem() {
        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .build();

        when(mockDataStore.getItem(criOAuthSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);

        var result =
                criOauthSessionService.getCriOauthSessionItem(
                        criOAuthSessionItem.getCriOAuthSessionId());

        verify(mockDataStore).getItem(criOAuthSessionItem.getCriOAuthSessionId());
        assertEquals(criOAuthSessionItem, result);
    }

    @Test
    void shouldRetryOnFailure() {
        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .build();

        when(mockDataStore.getItem(criOAuthSessionItem.getCriOAuthSessionId()))
                .thenReturn(null)
                .thenReturn(criOAuthSessionItem);

        var result =
                criOauthSessionService.getCriOauthSessionItem(
                        criOAuthSessionItem.getCriOAuthSessionId());

        verify(mockDataStore, times(2)).getItem(criOAuthSessionItem.getCriOAuthSessionId());
        assertEquals(criOAuthSessionItem, result);
    }

    @Test
    void shouldReturnNullIfMissingAfterRetries() {
        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .build();

        when(mockDataStore.getItem(criOAuthSessionItem.getCriOAuthSessionId())).thenReturn(null);

        var result =
                criOauthSessionService.getCriOauthSessionItem(
                        criOAuthSessionItem.getCriOAuthSessionId());

        assertNull(result);
    }

    @Test
    void shouldCreateCriOAuthSessionItem() throws Exception {
        var field = CriOAuthSessionService.class.getDeclaredField("configService");
        field.setAccessible(true);
        field.set(criOauthSessionService, mockConfigService);

        when(mockConfigService.getBackendSessionTtl()).thenReturn(900L);

        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId(ADDRESS.getId())
                        .connection("main")
                        .build();

        var result =
                criOauthSessionService.persistCriOAuthSession(
                        criOAuthSessionItem.getCriOAuthSessionId(),
                        ADDRESS,
                        criOAuthSessionItem.getClientOAuthSessionId(),
                        criOAuthSessionItem.getConnection());

        var captor = ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockDataStore).create(captor.capture(), eq(900L));

        assertEquals(criOAuthSessionItem.getCriOAuthSessionId(), result.getCriOAuthSessionId());
        assertEquals(criOAuthSessionItem.getCriId(), result.getCriId());
    }
}
