package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientAuthJwtIdItem;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientAuthJwtIdServiceTest {
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private DataStore<ClientAuthJwtIdItem> mockDataStore;
    @InjectMocks private ClientAuthJwtIdService clientAuthJwtIdService;

    @Test
    void shouldReturnClientAuthJwtIdItemGivenJwtId() {
        String testJwtId = "test-jwt-id";
        String testTimestamp = Instant.now().toString();
        ClientAuthJwtIdItem clientAuthJwtIdItem = new ClientAuthJwtIdItem(testJwtId, testTimestamp);
        when(mockDataStore.getItem(testJwtId)).thenReturn(clientAuthJwtIdItem);

        ClientAuthJwtIdItem result = clientAuthJwtIdService.getClientAuthJwtIdItem(testJwtId);

        assertNotNull(result.getJwtId());
        assertEquals(testJwtId, result.getJwtId());
    }

    @Test
    void shouldPersistClientAuthJwtId() {
        String testJwtId = "test-jwt-id";
        ArgumentCaptor<ClientAuthJwtIdItem> clientAuthJwtIdItemArgCaptor =
                ArgumentCaptor.forClass(ClientAuthJwtIdItem.class);

        clientAuthJwtIdService.persistClientAuthJwtId(testJwtId);

        verify(mockDataStore).create(clientAuthJwtIdItemArgCaptor.capture());
        ClientAuthJwtIdItem capturedClientAuthJwtIdItem = clientAuthJwtIdItemArgCaptor.getValue();
        assertNotNull(capturedClientAuthJwtIdItem);
        assertEquals(testJwtId, capturedClientAuthJwtIdItem.getJwtId());
    }
}
