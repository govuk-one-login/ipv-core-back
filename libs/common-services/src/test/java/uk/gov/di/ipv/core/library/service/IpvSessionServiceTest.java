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
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.dto.JourneyState;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
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
    private static final String IPV_SUCCESS_PAGE_STATE = "IPV_SUCCESS_PAGE";

    @Captor private ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor;
    @Mock private DataStore<IpvSessionItem> mockDataStore;
    @InjectMocks private IpvSessionService ipvSessionService;

    @Test
    void shouldReturnSessionItem() {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);
        ipvSessionItem.setUserState(START_STATE);
        ipvSessionItem.setCreationDateTime(new Date().toString());

        when(mockDataStore.getItem(ipvSessionID)).thenReturn(ipvSessionItem);

        IpvSessionItem result = ipvSessionService.getIpvSession(ipvSessionID);

        ArgumentCaptor<String> ipvSessionIDArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).getItem(ipvSessionIDArgumentCaptor.capture());
        assertEquals(ipvSessionID, ipvSessionIDArgumentCaptor.getValue());
        assertEquals(ipvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(ipvSessionItem.getUserState(), result.getUserState());
        assertEquals(ipvSessionItem.getCreationDateTime(), result.getCreationDateTime());
    }

    @Test
    void shouldReturnSessionItemByAuthorizationCode() {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        String authorizationCode = "12345";

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);

        when(mockDataStore.getItemByIndex(eq("authorizationCode"), anyString()))
                .thenReturn(ipvSessionItem);

        IpvSessionItem result =
                ipvSessionService.getIpvSessionByAuthorizationCode(authorizationCode).orElseThrow();

        assertEquals(result, ipvSessionItem);
    }

    @Test
    void shouldReturnSessionItemByAccessToken() {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        String accessToken = "56789";

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);

        when(mockDataStore.getItemByIndex(eq("accessToken"), anyString()))
                .thenReturn(ipvSessionItem);

        IpvSessionItem result =
                ipvSessionService.getIpvSessionByAccessToken(accessToken).orElseThrow();

        assertEquals(result, ipvSessionItem);
    }

    @Test
    void shouldRetryGettingSessionItemByAccessToken() {
        String ipvSessionID = SecureTokenHelper.getInstance().generate();
        String accessToken = "56789";

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);

        when(mockDataStore.getItemByIndex(eq("accessToken"), anyString()))
                .thenReturn(null, ipvSessionItem);

        IpvSessionItem result =
                ipvSessionService.getIpvSessionByAccessToken(accessToken).orElseThrow();

        assertEquals(result, ipvSessionItem);
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
        assertEquals(START_STATE, capturedSessionItem.getUserState());
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, START_STATE),
                capturedSessionItem.getStateStack().pop());
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
        assertEquals(START_STATE, capturedSessionItem.getUserState());
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
        assertEquals(TECHNICAL_ERROR, capturedSessionItem.getJourneyType());
        assertEquals(ERROR_STATE, capturedSessionItem.getUserState());
        assertEquals(testErrorObject.getCode(), capturedSessionItem.getErrorCode());
        assertEquals(testErrorObject.getDescription(), capturedSessionItem.getErrorDescription());
        assertEquals(
                new JourneyState(TECHNICAL_ERROR, ERROR_STATE),
                capturedSessionItem.getStateStack().pop());
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
        assertEquals(REVERIFICATION, capturedSessionItem.getJourneyType());
        assertEquals(
                new JourneyState(REVERIFICATION, START_STATE),
                capturedSessionItem.getStateStack().pop());
    }

    @Test
    void shouldUpdateSessionItem() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setUserState(START_STATE);
        ipvSessionItem.setCreationDateTime(new Date().toString());

        ipvSessionService.updateIpvSession(ipvSessionItem);

        verify(mockDataStore).update(ipvSessionItem);
    }

    @Test
    void shouldSetAuthorizationCodeAndMetadataOnSessionItem() {
        AuthorizationCode testCode = new AuthorizationCode();
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setUserState(IPV_SUCCESS_PAGE_STATE);
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
        ipvSessionItem.setUserState(IPV_SUCCESS_PAGE_STATE);
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
