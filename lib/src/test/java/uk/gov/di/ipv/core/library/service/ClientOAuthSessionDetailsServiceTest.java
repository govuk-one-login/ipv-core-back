package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

@ExtendWith(MockitoExtension.class)
class ClientOAuthSessionDetailsServiceTest {
    @Mock private DataStore<ClientOAuthSessionItem> mockDataStore;

    @Mock private ConfigService mockConfigService;

    @InjectMocks private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;

    @Test
    void shouldReturnClientOAuthSessionItem() {
        String clientOAuthSessionId = SecureTokenHelper.generate();

        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(clientOAuthSessionId);
        clientOAuthSessionItem.setResponseType("test-type");
        clientOAuthSessionItem.setClientId("test-client");
        clientOAuthSessionItem.setRedirectUri("http://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");

        when(mockDataStore.getItem(clientOAuthSessionId)).thenReturn(clientOAuthSessionItem);

        ClientOAuthSessionItem result =
                clientOAuthSessionDetailsService.getClientOAuthSession(clientOAuthSessionId);

        ArgumentCaptor<String> clientOAuthSessionIDArgumentCaptor =
                ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).getItem(clientOAuthSessionIDArgumentCaptor.capture());
        assertEquals(clientOAuthSessionId, clientOAuthSessionIDArgumentCaptor.getValue());
        assertEquals(
                clientOAuthSessionItem.getClientOAuthSessionId(), result.getClientOAuthSessionId());
        assertEquals(clientOAuthSessionItem.getResponseType(), result.getResponseType());
        assertEquals(clientOAuthSessionItem.getClientId(), result.getClientId());
        assertEquals(clientOAuthSessionItem.getRedirectUri(), result.getRedirectUri());
        assertEquals(clientOAuthSessionItem.getState(), result.getState());
        assertEquals(clientOAuthSessionItem.getUserId(), result.getUserId());
        assertEquals(
                clientOAuthSessionItem.getGovukSigninJourneyId(), result.getGovukSigninJourneyId());
    }

    @Test
    void shouldCreateClientOAuthSessionItem() throws ParseException {
        JWTClaimsSet testClaimSet =
                new JWTClaimsSet.Builder()
                        .claim("response_type", "test-type")
                        .claim("redirect_uri", "http://example.com")
                        .claim("state", "test-state")
                        .subject("test-user-id")
                        .build();
        ClientOAuthSessionItem clientOAuthSessionItem =
                clientOAuthSessionDetailsService.generateClientSessionDetails(
                        testClaimSet, "test-client");

        ArgumentCaptor<ClientOAuthSessionItem> clientOAuthSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(ClientOAuthSessionItem.class);
        verify(mockDataStore)
                .create(clientOAuthSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        assertEquals(
                clientOAuthSessionItem.getClientOAuthSessionId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getClientOAuthSessionId());
        assertEquals(
                clientOAuthSessionItem.getClientId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getClientId());
        assertEquals(
                clientOAuthSessionItem.getResponseType(),
                clientOAuthSessionItemArgumentCaptor.getValue().getResponseType());
        assertEquals(
                clientOAuthSessionItem.getRedirectUri(),
                clientOAuthSessionItemArgumentCaptor.getValue().getRedirectUri());
        assertEquals(
                clientOAuthSessionItem.getState(),
                clientOAuthSessionItemArgumentCaptor.getValue().getState());
        assertEquals(
                clientOAuthSessionItem.getUserId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getUserId());
        assertEquals(
                clientOAuthSessionItem.getGovukSigninJourneyId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getGovukSigninJourneyId());
    }

    @Test
    void shouldCreateSessionItemWithErrorObject() {
        ClientOAuthSessionItem clientOAuthSessionItem =
                clientOAuthSessionDetailsService.generateErrorClientSessionDetails(
                        "http://example.com", "test-client", "test-state", "test-journey-id");

        ArgumentCaptor<ClientOAuthSessionItem> clientOAuthSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(ClientOAuthSessionItem.class);
        verify(mockDataStore)
                .create(clientOAuthSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        assertNotNull(clientOAuthSessionItemArgumentCaptor.getValue().getClientOAuthSessionId());
        assertEquals(
                clientOAuthSessionItem.getClientOAuthSessionId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getClientOAuthSessionId());
        assertEquals(
                clientOAuthSessionItem.getClientId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getClientId());
        assertNull(clientOAuthSessionItem.getResponseType());
        assertEquals(
                clientOAuthSessionItem.getRedirectUri(),
                clientOAuthSessionItemArgumentCaptor.getValue().getRedirectUri());
        assertNull(clientOAuthSessionItem.getUserId());
        assertEquals(
                clientOAuthSessionItem.getState(),
                clientOAuthSessionItemArgumentCaptor.getValue().getState());
        assertEquals(
                clientOAuthSessionItem.getGovukSigninJourneyId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getGovukSigninJourneyId());
    }

    @Test
    void shouldUpdateSessionItem() {
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        clientOAuthSessionItem.setResponseType("test-type");
        clientOAuthSessionItem.setClientId("test-client");
        clientOAuthSessionItem.setRedirectUri("http://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");

        clientOAuthSessionDetailsService.updateClientOAuthSession(clientOAuthSessionItem);

        verify(mockDataStore).update(clientOAuthSessionItem);
    }
}
