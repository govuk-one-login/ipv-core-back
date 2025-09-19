package uk.gov.di.ipv.core.issueclientaccesstoken.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientAuthJwtIdServiceTest {
    @Mock private DataStore<ClientAuthJwtIdItem> mockDataStore;
    @Mock private ConfigService mockConfigService;

    private ClientAuthJwtIdService clientAuthJwtIdService;

    @BeforeEach
    void setUp() {
        clientAuthJwtIdService = new ClientAuthJwtIdService(mockDataStore, mockConfigService);
    }

    @Test
    void shouldReturnClientAuthJwtIdItemGivenJwtId() {
        String testJwtId = "test-jwt-id";
        String testTimestamp = Instant.now().toString();
        var item = new ClientAuthJwtIdItem(testJwtId, testTimestamp);

        when(mockDataStore.getItem(testJwtId)).thenReturn(item);

        var result = clientAuthJwtIdService.getClientAuthJwtIdItem(testJwtId);

        assertNotNull(result.getJwtId());
        assertEquals(testJwtId, result.getJwtId());
    }

    @Test
    void shouldPersistClientAuthJwtId() {
        when(mockConfigService.getBackendSessionTtl()).thenReturn(900L);

        String testJwtId = "test-jwt-id";
        var captor = ArgumentCaptor.forClass(ClientAuthJwtIdItem.class);

        clientAuthJwtIdService.persistClientAuthJwtId(testJwtId);

        verify(mockDataStore).create(captor.capture(), eq(900L));
        assertNotNull(captor.getValue());
        assertEquals(testJwtId, captor.getValue().getJwtId());
    }
}
