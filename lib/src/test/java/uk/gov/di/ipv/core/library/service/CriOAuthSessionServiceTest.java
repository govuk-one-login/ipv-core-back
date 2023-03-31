package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
                        .userId("testUserId")
                        .govukSigninJourneyId("testGovUKSignInJourneyId")
                        .creationDateTime(Instant.now().toString())
                        .journeyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY)
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
        assertEquals(criOAuthSessionItem.getUserId(), result.getUserId());
        assertEquals(
                criOAuthSessionItem.getGovukSigninJourneyId(), result.getGovukSigninJourneyId());
        assertEquals(criOAuthSessionItem.getTtl(), result.getTtl());
        assertEquals(criOAuthSessionItem.getCreationDateTime(), result.getCreationDateTime());
        assertEquals(criOAuthSessionItem.getJourneyType(), result.getJourneyType());
    }

    @Test
    void shouldCreateCriOAuthSessionItem() {
        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .accessToken("testAccessToken")
                        .authorizationCode("testAuthorizationCode")
                        .userId("testUserId")
                        .govukSigninJourneyId("testGovUKSignInJourneyId")
                        .journeyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY)
                        .build();

        CriOAuthSessionItem result =
                criOauthSessionService.persistCriOAuthSession(
                        criOAuthSessionItem.getCriOAuthSessionId(),
                        criOAuthSessionItem.getCriId(),
                        criOAuthSessionItem.getUserId(),
                        criOAuthSessionItem.getGovukSigninJourneyId());

        ArgumentCaptor<CriOAuthSessionItem> criOAuthSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockDataStore)
                .create(criOAuthSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));

        assertNotNull(result.getCreationDateTime());
        assertEquals(criOAuthSessionItem.getCriOAuthSessionId(), result.getCriOAuthSessionId());
        assertEquals(criOAuthSessionItem.getCriId(), result.getCriId());
        assertNull(result.getAccessToken());
        assertNull(result.getAuthorizationCode());
        assertEquals(criOAuthSessionItem.getUserId(), result.getUserId());
        assertEquals(
                criOAuthSessionItem.getGovukSigninJourneyId(), result.getGovukSigninJourneyId());
        assertEquals(criOAuthSessionItem.getTtl(), result.getTtl());
        assertEquals(criOAuthSessionItem.getJourneyType(), result.getJourneyType());
    }

    @Test
    void shouldUpdateSessionItem() {
        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testAddress")
                        .accessToken("testAccessToken")
                        .authorizationCode("testAuthorizationCode")
                        .userId("testUserId")
                        .govukSigninJourneyId("testGovUKSignInJourneyId")
                        .creationDateTime(Instant.now().toString())
                        .journeyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY)
                        .build();

        criOauthSessionService.updateCriOAuthSessionItem(criOAuthSessionItem);

        verify(mockDataStore).update(criOAuthSessionItem);
    }
}
