package uk.gov.di.ipv.core.issueclientaccesstoken.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.library.persistence.DataStore;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

@ExtendWith(MockitoExtension.class)
class ClientAuthJwtIdServiceTest {
    @Mock private DataStore<ClientAuthJwtIdItem> mockDataStore;

    @Test
    void shouldReturnClientAuthJwtIdItemGivenJwtId() {
        String testJwtId = "test-jwt-id";
        String testTimestamp = Instant.now().toString();
        ClientAuthJwtIdItem clientAuthJwtIdItem = new ClientAuthJwtIdItem(testJwtId, testTimestamp);
        when(mockDataStore.getItem(testJwtId)).thenReturn(clientAuthJwtIdItem);
        var clientAuthJwtIdService = new ClientAuthJwtIdService(mockDataStore);

        ClientAuthJwtIdItem result = clientAuthJwtIdService.getClientAuthJwtIdItem(testJwtId);

        assertNotNull(result.getJwtId());
        assertEquals(testJwtId, result.getJwtId());
    }

    @Test
    void shouldPersistClientAuthJwtId() {
        String testJwtId = "test-jwt-id";
        ArgumentCaptor<ClientAuthJwtIdItem> clientAuthJwtIdItemArgCaptor =
                ArgumentCaptor.forClass(ClientAuthJwtIdItem.class);
        var clientAuthJwtIdService = new ClientAuthJwtIdService(mockDataStore);

        clientAuthJwtIdService.persistClientAuthJwtId(testJwtId);

        verify(mockDataStore)
                .create(clientAuthJwtIdItemArgCaptor.capture(), eq(BACKEND_SESSION_TTL));
        ClientAuthJwtIdItem capturedClientAuthJwtIdItem = clientAuthJwtIdItemArgCaptor.getValue();
        assertNotNull(capturedClientAuthJwtIdItem);
        assertEquals(testJwtId, capturedClientAuthJwtIdItem.getJwtId());
    }
}
