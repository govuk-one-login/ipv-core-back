package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnknownAccessTokenException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.retry.Sleeper;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.REVERIFICATION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.TECHNICAL_ERROR;

@ExtendWith(MockitoExtension.class)
class IpvSessionServiceTest {
    private static final String START_STATE = "START";
    private static final String ERROR_STATE = "ERROR";
    private static final JourneyState INITIAL_START_JOURNEY_STATE =
            new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE);

    @Captor private ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor;
    @Mock private DataStore<IpvSessionItem> mockDataStore;
    @Mock private Sleeper mockSleeper;
    @InjectMocks private IpvSessionService ipvSessionService;

    @Test
    void shouldReturnSessionItem() throws UnknownAccessTokenException, IpvSessionNotFoundException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
        ipvSessionItem.setCreationDateTime(new Date().toString());

        when(mockDataStore.getItem(ipvSessionID)).thenReturn(ipvSessionItem);

        IpvSessionItem result = ipvSessionService.getIpvSession(ipvSessionID);

        ArgumentCaptor<String> ipvSessionIDArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).getItem(ipvSessionIDArgumentCaptor.capture());
        assertEquals(ipvSessionID, ipvSessionIDArgumentCaptor.getValue());
        assertEquals(ipvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(ipvSessionItem.getState(), result.getState());
        assertEquals(ipvSessionItem.getCreationDateTime(), result.getCreationDateTime());
    }

    @Test
    void shouldReturnSessionItemWithRetry()
            throws UnknownAccessTokenException, IpvSessionNotFoundException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
        ipvSessionItem.setCreationDateTime(new Date().toString());

        when(mockDataStore.getItem(ipvSessionID)).thenReturn(ipvSessionItem);

        IpvSessionItem result = ipvSessionService.getIpvSession(ipvSessionID, true);

        ArgumentCaptor<String> ipvSessionIDArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).getItem(ipvSessionIDArgumentCaptor.capture());
        assertEquals(ipvSessionID, ipvSessionIDArgumentCaptor.getValue());
        assertEquals(ipvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(ipvSessionItem.getState(), result.getState());
        assertEquals(ipvSessionItem.getCreationDateTime(), result.getCreationDateTime());
    }

    @Test
    void shouldReturnExceptionWithAllFailedRetries() throws UnknownAccessTokenException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
        ipvSessionItem.setCreationDateTime(new Date().toString());

        when(mockDataStore.getItem(ipvSessionID))
                .thenReturn(null, null, null, null, null, null, null);

        assertThrows(
                IpvSessionNotFoundException.class,
                () -> ipvSessionService.getIpvSession(ipvSessionID, true));
    }

    @Test
    void shouldReturnInterruptedExceptionWithRetry()
            throws UnknownAccessTokenException, InterruptedException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        doThrow(new InterruptedException()).when(mockSleeper).sleep(anyLong());

        when(mockDataStore.getItem(ipvSessionID)).thenReturn(null, null, null);

        assertThrows(
                IpvSessionNotFoundException.class,
                () -> ipvSessionService.getIpvSession(ipvSessionID, true));
    }

    @Test
    void shouldReturnSessionItemByAuthorizationCode() throws IpvSessionNotFoundException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        String authorizationCode = "12345";

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);

        when(mockDataStore.getItemByIndex(eq("authorizationCode"), anyString()))
                .thenReturn(ipvSessionItem);

        IpvSessionItem result =
                ipvSessionService.getIpvSessionByAuthorizationCode(authorizationCode);

        assertEquals(result, ipvSessionItem);
    }

    @Test
    void shouldReturnSessionItemByAccessToken()
            throws UnknownAccessTokenException, IpvSessionNotFoundException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        String accessToken = "56789";

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);

        when(mockDataStore.getItemByIndex(eq("accessToken"), anyString()))
                .thenReturn(ipvSessionItem);

        IpvSessionItem result = ipvSessionService.getIpvSessionByAccessToken(accessToken);

        assertEquals(result, ipvSessionItem);
    }

    @Test
    void shouldRetryGettingSessionItemByAccessToken() throws Exception {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        String accessToken = "56789";

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);

        when(mockDataStore.getItemByIndex(eq("accessToken"), anyString()))
                .thenReturn(null, null, null, null, null, ipvSessionItem);

        IpvSessionItem result = ipvSessionService.getIpvSessionByAccessToken(accessToken);

        assertEquals(result, ipvSessionItem);

        var inOrder = inOrder(mockSleeper);
        inOrder.verify(mockSleeper, times(1)).sleep(10);
        inOrder.verify(mockSleeper, times(1)).sleep(20);
        inOrder.verify(mockSleeper, times(1)).sleep(40);
        inOrder.verify(mockSleeper, times(1)).sleep(80);
        inOrder.verify(mockSleeper, times(1)).sleep(160);
        inOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldCreateSessionItem() {
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), null, null, false);

        verify(mockDataStore)
                .create(ipvSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        var capturedSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertNotNull(capturedSessionItem.getIpvSessionId());
        assertNotNull(capturedSessionItem.getCreationDateTime());

        assertEquals(ipvSessionItem.getIpvSessionId(), capturedSessionItem.getIpvSessionId());
        assertEquals(INITIAL_START_JOURNEY_STATE, capturedSessionItem.getState());
    }

    @Test
    void shouldCreateSessionItemWithEmail() {
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), null, "test@test.com", false);

        verify(mockDataStore)
                .create(ipvSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        var capturedSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertNotNull(capturedSessionItem.getIpvSessionId());
        assertNotNull(capturedSessionItem.getCreationDateTime());

        assertEquals(capturedSessionItem.getIpvSessionId(), ipvSessionItem.getIpvSessionId());
        assertEquals(INITIAL_START_JOURNEY_STATE, capturedSessionItem.getState());
        assertEquals("test@test.com", capturedSessionItem.getEmailAddress());
    }

    @Test
    void shouldCreateSessionItemWithErrorObject() {
        ErrorObject testErrorObject = new ErrorObject("server_error", "Test error");
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), testErrorObject, null, false);

        verify(mockDataStore)
                .create(ipvSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        var capturedSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertNotNull(capturedSessionItem.getIpvSessionId());
        assertNotNull(capturedSessionItem.getCreationDateTime());
        assertEquals(capturedSessionItem.getIpvSessionId(), ipvSessionItem.getIpvSessionId());
        assertEquals(testErrorObject.getCode(), capturedSessionItem.getErrorCode());
        assertEquals(testErrorObject.getDescription(), capturedSessionItem.getErrorDescription());
        assertEquals(
                new JourneyState(TECHNICAL_ERROR, ERROR_STATE), capturedSessionItem.getState());
    }

    @Test
    void shouldCreateSessionItemWithReverificationJourney() {
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), null, null, true);

        verify(mockDataStore)
                .create(ipvSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        var capturedSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertNotNull(capturedSessionItem.getIpvSessionId());
        assertNotNull(capturedSessionItem.getCreationDateTime());
        assertEquals(ipvSessionItem.getIpvSessionId(), capturedSessionItem.getIpvSessionId());
        assertEquals(new JourneyState(REVERIFICATION, START_STATE), capturedSessionItem.getState());
    }

    @Test
    void shouldUpdateSessionItem() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
        ipvSessionItem.setCreationDateTime(new Date().toString());

        ipvSessionService.updateIpvSession(ipvSessionItem);

        verify(mockDataStore).update(ipvSessionItem);
    }

    @Test
    void shouldSetAuthorizationCodeAndMetadataOnSessionItem() {
        AuthorizationCode testCode = new AuthorizationCode();
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setCreationDateTime(new Date().toString());

        ipvSessionService.setAuthorizationCode(
                ipvSessionItem, testCode.getValue(), "http://example.com");

        verify(mockDataStore).update(ipvSessionItemArgumentCaptor.capture());
        assertNotNull(ipvSessionItemArgumentCaptor.getValue().getAuthorizationCode());
        assertNotNull(ipvSessionItemArgumentCaptor.getValue().getAuthorizationCodeMetadata());
    }

    @Test
    void shouldSetAccessTokenAndMetadataOnSessionItem() {
        BearerAccessToken accessToken = new BearerAccessToken("test-access-token");
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setCreationDateTime(new Date().toString());

        ipvSessionService.setAccessToken(ipvSessionItem, accessToken);

        verify(mockDataStore).update(ipvSessionItemArgumentCaptor.capture());
        assertNotNull(ipvSessionItemArgumentCaptor.getValue().getAccessToken());
        assertNotNull(ipvSessionItemArgumentCaptor.getValue().getAccessTokenMetadata());
    }

    @Test
    void shouldRevokeAccessTokenOnSessionItem() {
        BearerAccessToken accessToken = new BearerAccessToken("test-access-token");
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setAccessToken(accessToken.getValue());
        ipvSessionItem.setAccessTokenMetadata(new AccessTokenMetadata());

        ipvSessionService.revokeAccessToken(ipvSessionItem);

        verify(mockDataStore).update(ipvSessionItemArgumentCaptor.capture());
        assertNotNull(
                ipvSessionItemArgumentCaptor
                        .getValue()
                        .getAccessTokenMetadata()
                        .getRevokedAtDateTime());
    }
}
