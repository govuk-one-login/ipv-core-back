package uk.gov.di.ipv.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.IpvSessionItem;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class IpvSessionServiceTest {

    @Mock
    DataStore<IpvSessionItem> mockDataStore;

    @Mock
    ConfigurationService mockConfigurationService;

    private IpvSessionService ipvSessionService;

    @BeforeEach
    void setUp() {
        ipvSessionService = new IpvSessionService(mockDataStore, mockConfigurationService);
    }

    @Test
    void shouldCreateSessionItem() {
        String userId = UUID.randomUUID().toString();

        IpvSessionItem ipvSessionItem = ipvSessionService.generateIpvSession();

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor = ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture());
        assertNotNull(ipvSessionItemArgumentCaptor.getValue().getIpvSessionId());
        assertNotNull(ipvSessionItemArgumentCaptor.getValue().getCreationDateTime());

        assertEquals(ipvSessionItemArgumentCaptor.getValue().getIpvSessionId(), ipvSessionItem.getIpvSessionId());
        assertEquals(ipvSessionItemArgumentCaptor.getValue().getCreationDateTime(), ipvSessionItem.getCreationDateTime());
    }
}
