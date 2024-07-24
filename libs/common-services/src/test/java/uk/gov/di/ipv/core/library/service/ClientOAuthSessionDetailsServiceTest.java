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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

@ExtendWith(MockitoExtension.class)
class ClientOAuthSessionDetailsServiceTest {
    @Mock private DataStore<ClientOAuthSessionItem> mockDataStore;

    @InjectMocks private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;

    @Test
    void shouldReturnClientOAuthSessionItem() {
        String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(clientOAuthSessionId);
        clientOAuthSessionItem.setResponseType("test-type");
        clientOAuthSessionItem.setClientId("test-client");
        clientOAuthSessionItem.setRedirectUri("http://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        clientOAuthSessionItem.setReproveIdentity(true);

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
        assertEquals(clientOAuthSessionItem.getReproveIdentity(), result.getReproveIdentity());
    }

    @Test
    void shouldCreateClientOAuthSessionItem() throws ParseException {
        String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

        JWTClaimsSet testClaimSet =
                new JWTClaimsSet.Builder()
                        .claim("response_type", "test-type")
                        .claim("redirect_uri", "http://example.com")
                        .claim("state", "test-state")
                        .claim("govuk_signin_journey_id", "test-journey-id")
                        .claim("reprove_identity", false)
                        .claim("scope", "test-scope")
                        .claim("vtr", List.of("P1"))
                        .subject("test-user-id")
                        .build();
        ClientOAuthSessionItem clientOAuthSessionItem =
                clientOAuthSessionDetailsService.generateClientSessionDetails(
                        clientOAuthSessionId,
                        testClaimSet,
                        "test-client",
                        "test-evcs-access-token");

        ArgumentCaptor<ClientOAuthSessionItem> clientOAuthSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(ClientOAuthSessionItem.class);
        verify(mockDataStore)
                .create(clientOAuthSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        assertEquals(clientOAuthSessionId, clientOAuthSessionItem.getClientOAuthSessionId());
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
                clientOAuthSessionItem.getEvcsAccessToken(),
                clientOAuthSessionItemArgumentCaptor.getValue().getEvcsAccessToken());
        assertEquals(
                clientOAuthSessionItem.getGovukSigninJourneyId(),
                clientOAuthSessionItemArgumentCaptor.getValue().getGovukSigninJourneyId());
        assertEquals(
                clientOAuthSessionItem.getScope(),
                clientOAuthSessionItemArgumentCaptor.getValue().getScope());
        assertFalse(clientOAuthSessionItem.getReproveIdentity());
        assertEquals(
                clientOAuthSessionItem.getVtr(),
                clientOAuthSessionItemArgumentCaptor.getValue().getVtr());
    }

    @Test
    void shouldCreateSessionItemWithErrorObject() {
        String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();
        ClientOAuthSessionItem clientOAuthSessionItem =
                clientOAuthSessionDetailsService.generateErrorClientSessionDetails(
                        clientOAuthSessionId,
                        "http://example.com",
                        "test-client",
                        "test-state",
                        "test-journey-id");

        ArgumentCaptor<ClientOAuthSessionItem> clientOAuthSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(ClientOAuthSessionItem.class);
        verify(mockDataStore)
                .create(clientOAuthSessionItemArgumentCaptor.capture(), eq(BACKEND_SESSION_TTL));
        assertNotNull(clientOAuthSessionItemArgumentCaptor.getValue().getClientOAuthSessionId());
        assertEquals(clientOAuthSessionId, clientOAuthSessionItem.getClientOAuthSessionId());
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
        assertNull(clientOAuthSessionItem.getReproveIdentity());
    }
}
