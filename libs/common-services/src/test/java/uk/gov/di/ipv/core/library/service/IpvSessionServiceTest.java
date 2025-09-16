package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.*;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.REVERIFICATION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.TECHNICAL_ERROR;

@ExtendWith(MockitoExtension.class)
class IpvSessionServiceTest {
    private static final String START_STATE = "START";
    private static final String ERROR_STATE = "ERROR";
    private static final JourneyState INITIAL_START_JOURNEY_STATE =
            new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE);
    private static final String ACCOUNT_INTERVENTION_ERROR_DESCRIPTION =
            "Account intervention detected";

    @Captor private ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor;
    @Mock private DataStore<IpvSessionItem> mockDataStore;
    @Mock private Sleeper mockSleeper;
    private IpvSessionService ipvSessionService;
    @Mock private ConfigService mockConfigService;

    @BeforeEach
    void setUp() throws Exception {
        // Use the ctor that does not try to build its own datastore
        ipvSessionService = new IpvSessionService(mockDataStore, mockSleeper);

        // Inject the mock ConfigService into the private field
        var field = IpvSessionService.class.getDeclaredField("configService");
        field.setAccessible(true);
        field.set(ipvSessionService, mockConfigService);
    }

    @Test
    void shouldReturnSessionItem() throws IpvSessionNotFoundException {
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
    void shouldReturnSessionItemWithRetry() throws IpvSessionNotFoundException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
        ipvSessionItem.setCreationDateTime(new Date().toString());

        when(mockDataStore.getItem(ipvSessionID)).thenReturn(ipvSessionItem);

        IpvSessionItem result = ipvSessionService.getIpvSessionWithRetry(ipvSessionID);

        ArgumentCaptor<String> ipvSessionIDArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).getItem(ipvSessionIDArgumentCaptor.capture());
        assertEquals(ipvSessionID, ipvSessionIDArgumentCaptor.getValue());
        assertEquals(ipvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(ipvSessionItem.getState(), result.getState());
        assertEquals(ipvSessionItem.getCreationDateTime(), result.getCreationDateTime());
    }

    @Test
    void shouldReturnExceptionWithAllFailedRetries() {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
        ipvSessionItem.setCreationDateTime(new Date().toString());

        when(mockDataStore.getItem(ipvSessionID))
                .thenReturn(null, null, null, null, null, null, null);

        assertThrows(
                IpvSessionNotFoundException.class,
                () -> ipvSessionService.getIpvSessionWithRetry(ipvSessionID));
    }

    @Test
    void shouldReturnInterruptedExceptionWithRetry() throws InterruptedException {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        doThrow(new InterruptedException()).when(mockSleeper).sleep(anyLong());

        when(mockDataStore.getItem(ipvSessionID)).thenReturn(null, null, null);

        assertThrows(
                IpvSessionNotFoundException.class,
                () -> ipvSessionService.getIpvSessionWithRetry(ipvSessionID));
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
    void shouldReturnSessionItemByAccessToken() throws IpvSessionNotFoundException {
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
                .thenReturn(null)
                .thenReturn(ipvSessionItem);

        IpvSessionItem result = ipvSessionService.getIpvSessionByAccessToken(accessToken);

        assertEquals(result, ipvSessionItem);
    }

    @Test
    void shouldReturnSessionItemByClientOAuthSessionId() throws IpvSessionNotFoundException {
        // Arrange
        var ipvSessionId = SecureTokenHelper.getInstance().generate();
        var clientOAuthSessionId = "56789";

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionId);

        when(mockDataStore.getItemByIndex("clientOAuthSessionId", clientOAuthSessionId))
                .thenReturn(ipvSessionItem);

        // Act
        IpvSessionItem result =
                ipvSessionService.getIpvSessionByClientOAuthSessionId(clientOAuthSessionId);

        // Assert
        assertEquals(result, ipvSessionItem);
    }

    @Test
    void shouldCreateSessionItem() {
        when(mockConfigService.getBackendSessionTtl()).thenReturn(900L);
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), null, null, false);

        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture(), eq(900L));
        var capturedSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertNotNull(capturedSessionItem.getIpvSessionId());
        assertNotNull(capturedSessionItem.getCreationDateTime());

        assertEquals(ipvSessionItem.getIpvSessionId(), capturedSessionItem.getIpvSessionId());
        assertEquals(INITIAL_START_JOURNEY_STATE, capturedSessionItem.getState());
    }

    @Test
    void shouldCreateSessionItemWithEmail() {
        when(mockConfigService.getBackendSessionTtl()).thenReturn(900L);
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), null, "test@test.com", false);

        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture(), eq(900L));
        var capturedSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertNotNull(capturedSessionItem.getIpvSessionId());
        assertNotNull(capturedSessionItem.getCreationDateTime());

        assertEquals(capturedSessionItem.getIpvSessionId(), ipvSessionItem.getIpvSessionId());
        assertEquals(INITIAL_START_JOURNEY_STATE, capturedSessionItem.getState());
        assertEquals("test@test.com", capturedSessionItem.getEmailAddress());
    }

    @Test
    void shouldCreateSessionItemWithErrorObject() {
        when(mockConfigService.getBackendSessionTtl()).thenReturn(900L);
        ErrorObject testErrorObject = new ErrorObject("server_error", "Test error");
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), testErrorObject, null, false);

        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture(), eq(900L));
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
<<<<<<< HEAD
=======
    void shouldCreateSessionItemWithInitialAccountState() {
        when(mockConfigService.getBackendSessionTtl()).thenReturn(900L);
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(),
                        null,
                        null,
                        false,
                        ACCOUNT_INTERVENTION_STATE,
                        AIS_NO_INTERVENTION);

        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture(), eq(900L));
        var capturedSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertNotNull(capturedSessionItem.getIpvSessionId());
        assertNotNull(capturedSessionItem.getCreationDateTime());

        assertEquals(capturedSessionItem.getIpvSessionId(), ipvSessionItem.getIpvSessionId());
        assertEquals(INITIAL_START_JOURNEY_STATE, capturedSessionItem.getState());
        assertEquals(
                ACCOUNT_INTERVENTION_STATE,
                capturedSessionItem.getInitialAccountInterventionState());
        assertEquals(AIS_NO_INTERVENTION, capturedSessionItem.getAisInterventionType());
    }

    @Test
>>>>>>> be9286379 (PYIC-7878: Refactor TTL handling & fix tests: use typed config getters)
    void shouldCreateSessionItemWithReverificationJourney() {
        when(mockConfigService.getBackendSessionTtl()).thenReturn(900L);
        IpvSessionItem ipvSessionItem =
                ipvSessionService.generateIpvSession(
                        SecureTokenHelper.getInstance().generate(), null, null, true);

        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture(), eq(900L));
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
    void shouldInvalidateSessionItem() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE));
        ipvSessionItem.setCreationDateTime(new Date().toString());

        ipvSessionService.invalidateSession(ipvSessionItem, ACCOUNT_INTERVENTION_ERROR_DESCRIPTION);

        verify(mockDataStore).update(ipvSessionItemArgumentCaptor.capture());
        assertEquals("session_invalidated", ipvSessionItemArgumentCaptor.getValue().getErrorCode());
        assertEquals(
                "Account intervention detected",
                ipvSessionItemArgumentCaptor.getValue().getErrorDescription());
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
