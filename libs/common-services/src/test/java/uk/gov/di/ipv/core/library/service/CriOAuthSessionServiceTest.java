package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.commons.util.StringUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.retry.Sleeper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;

@ExtendWith(MockitoExtension.class)
class CriOAuthSessionServiceTest {
    @Mock private DataStore<CriOAuthSessionItem> mockDataStore;
    @Mock private Sleeper mockSleeper;
    @InjectMocks private CriOAuthSessionService criOauthSessionService;

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
    void shouldCreateCriOAuthSessionItem() {
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

        var criOAuthSessionItemArgumentCaptor = ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockDataStore)
                .create(criOAuthSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));

        assertEquals(criOAuthSessionItem.getCriOAuthSessionId(), result.getCriOAuthSessionId());
        assertEquals(criOAuthSessionItem.getCriId(), result.getCriId());
    }

    @Test
    void shouldUpdateCriOAuthSessionItemWithLockTimestamp() {
        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId(ADDRESS.getId())
                        .connection("main")
                        .build();

        criOauthSessionService.setLockedTimestamp(criOAuthSessionItem);

        var criOAuthSessionItemArgumentCaptor = ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockDataStore, times(1)).update(criOAuthSessionItemArgumentCaptor.capture());
        assertTrue(
                StringUtils.isNotBlank(
                        criOAuthSessionItemArgumentCaptor.getValue().getLockedTimestamp()));
    }

    @Test
    void shouldUpdateCriOAuthSessionItemWithJourneyResult() {
        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId(ADDRESS.getId())
                        .connection("main")
                        .build();

        criOauthSessionService.setProcessedResult(criOAuthSessionItem, "some-journey-result");

        var criOAuthSessionItemArgumentCaptor = ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockDataStore, times(1)).update(criOAuthSessionItemArgumentCaptor.capture());
        assertEquals(
                "some-journey-result",
                criOAuthSessionItemArgumentCaptor.getValue().getProcessedResult());
    }
}
