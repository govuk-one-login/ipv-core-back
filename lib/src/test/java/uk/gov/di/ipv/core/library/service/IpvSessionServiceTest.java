package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IpvSessionServiceTest {

    @Mock private DataStore<IpvSessionItem> mockDataStore;

    @Mock private ConfigurationService mockConfigurationService;

    @InjectMocks private IpvSessionService ipvSessionService;

    @Test
    void shouldReturnSessionItem() {
        String ipvSessionID = UUID.randomUUID().toString();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(ipvSessionID);
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());
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
    void shouldCreateSessionItem() {
        when(mockConfigurationService.getBackendSessionTimeout()).thenReturn("7200");
        String ipvSessionID =
                ipvSessionService.generateIpvSession(
                        new ClientSessionDetailsDto(
                                "jwt",
                                "test-client",
                                "http://example.come",
                                "test-state",
                                "test-user-id",
                                false));

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem capturedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();

        assertNotNull(capturedIpvSessionItem.getIpvSessionId());
        assertNotNull(capturedIpvSessionItem.getCreationDateTime());
        assertNotNull(capturedIpvSessionItem.getExpirationDateTime());
        assertEquals(
                7200,
                Instant.parse(capturedIpvSessionItem.getExpirationDateTime()).getEpochSecond()
                        - Instant.parse(capturedIpvSessionItem.getCreationDateTime())
                                .getEpochSecond());

        assertEquals(capturedIpvSessionItem.getIpvSessionId(), ipvSessionID);
        assertEquals(
                UserStates.INITIAL_IPV_JOURNEY.toString(), capturedIpvSessionItem.getUserState());
    }

    @Test
    void shouldCreateSessionItemForDebugJourney() {
        when(mockConfigurationService.getBackendSessionTimeout()).thenReturn("7200");
        String ipvSessionID =
                ipvSessionService.generateIpvSession(
                        new ClientSessionDetailsDto(
                                "jwt",
                                "test-client",
                                "http://example.come",
                                "test-state",
                                "test-user-id",
                                true));

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem capturedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();

        assertNotNull(capturedIpvSessionItem.getIpvSessionId());
        assertNotNull(capturedIpvSessionItem.getCreationDateTime());
        assertNotNull(capturedIpvSessionItem.getExpirationDateTime());
        assertEquals(
                7200,
                Instant.parse(capturedIpvSessionItem.getExpirationDateTime()).getEpochSecond()
                        - Instant.parse(capturedIpvSessionItem.getCreationDateTime())
                                .getEpochSecond());

        assertEquals(capturedIpvSessionItem.getIpvSessionId(), ipvSessionID);
        assertEquals(UserStates.DEBUG_PAGE.toString(), capturedIpvSessionItem.getUserState());
    }

    @Test
    void shouldUpdateSessionItem() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());

        ipvSessionService.updateIpvSession(ipvSessionItem);

        verify(mockDataStore).update(ipvSessionItem);
    }
}
