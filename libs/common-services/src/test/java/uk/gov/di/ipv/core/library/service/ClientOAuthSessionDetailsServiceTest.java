package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;

import java.text.ParseException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientOAuthSessionDetailsServiceTest {
    @Mock private DataStore<ClientOAuthSessionItem> mockDataStore;
    @Mock private ConfigService mockConfigService;

    @Test
    void shouldReturnClientOAuthSessionItem() throws Exception {
        var clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

        var clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(clientOAuthSessionId);
        clientOAuthSessionItem.setResponseType("test-type");
        clientOAuthSessionItem.setClientId("test-client");
        clientOAuthSessionItem.setRedirectUri("http://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        clientOAuthSessionItem.setReproveIdentity(true);

        when(mockDataStore.getItem(clientOAuthSessionId)).thenReturn(clientOAuthSessionItem);

        var clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(mockDataStore, mockConfigService);

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
    void shouldThrowIfNoClientOauthSessionItem() {
        var clientOAuthSessionId = SecureTokenHelper.getInstance().generate();
        when(mockDataStore.getItem(clientOAuthSessionId)).thenReturn(null);

        var clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(mockDataStore, mockConfigService);

        assertThrows(
                ClientOauthSessionNotFoundException.class,
                () -> clientOAuthSessionDetailsService.getClientOAuthSession(clientOAuthSessionId));
    }

    @Test
    void shouldCreateClientOAuthSessionItem() throws ParseException {

        var clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

        var testClaimSet =
                new JWTClaimsSet.Builder()
                        .claim("response_type", "test-type")
                        .claim("redirect_uri", "http://example.com")
                        .claim("state", "test-state")
                        .claim("govuk_signin_journey_id", "test-journey-id")
                        .claim("reprove_identity", false)
                        .claim("scope", "test-scope")
                        .claim("vtr", List.of("P1", "P2"))
                        .subject("test-user-id")
                        .build();

        var clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(mockDataStore, mockConfigService);

        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.generateClientSessionDetails(
                        clientOAuthSessionId,
                        testClaimSet,
                        "test-client",
                        "test-evcs-access-token");

        verify(mockDataStore)
                .create(clientOAuthSessionItem, mockConfigService.getBackendSessionTtl());

        assertEquals(clientOAuthSessionId, clientOAuthSessionItem.getClientOAuthSessionId());
        assertEquals("test-client", clientOAuthSessionItem.getClientId());
        assertEquals("test-type", clientOAuthSessionItem.getResponseType());
        assertEquals("http://example.com", clientOAuthSessionItem.getRedirectUri());
        assertEquals("test-state", clientOAuthSessionItem.getState());
        assertEquals("test-user-id", clientOAuthSessionItem.getUserId());
        assertEquals("test-evcs-access-token", clientOAuthSessionItem.getEvcsAccessToken());
        assertEquals("test-journey-id", clientOAuthSessionItem.getGovukSigninJourneyId());
        assertEquals("test-scope", clientOAuthSessionItem.getScope());
        assertFalse(clientOAuthSessionItem.getReproveIdentity());
        assertEquals(List.of("P1", "P2"), clientOAuthSessionItem.getVtr());
    }

    @Test
    void shouldUpdateClientOAuthSessionItem() {
        // Arrange
        var clientOAuthSessionItem = new ClientOAuthSessionItem();
        var underTest = new ClientOAuthSessionDetailsService(mockDataStore, mockConfigService);

        // Act
        underTest.updateClientSessionDetails(clientOAuthSessionItem);

        // Assert
        verify(mockDataStore).update(clientOAuthSessionItem);
    }

    @Test
    void shouldCreateSessionItemWithErrorObject() {
        var clientOAuthSessionId = SecureTokenHelper.getInstance().generate();
        var clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(mockDataStore, mockConfigService);

        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.generateErrorClientSessionDetails(
                        clientOAuthSessionId,
                        "http://example.com",
                        "test-client",
                        "test-state",
                        "test-journey-id");

        verify(mockDataStore)
                .create(clientOAuthSessionItem, mockConfigService.getBackendSessionTtl());

        assertEquals(clientOAuthSessionId, clientOAuthSessionItem.getClientOAuthSessionId());
        assertEquals("test-client", clientOAuthSessionItem.getClientId());
        assertEquals("http://example.com", clientOAuthSessionItem.getRedirectUri());
        assertEquals("test-state", clientOAuthSessionItem.getState());
        assertEquals("test-journey-id", clientOAuthSessionItem.getGovukSigninJourneyId());
        assertTrue(clientOAuthSessionItem.isErrorClientSession());
    }
}
