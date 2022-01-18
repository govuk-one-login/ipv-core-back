package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class IpvSessionServiceTest {

  @Mock private DataStore<IpvSessionItem> mockDataStore;

  @Mock private ConfigurationService mockConfigurationService;

  private IpvSessionService ipvSessionService;

  @BeforeEach
  void setUp() {
    ipvSessionService = new IpvSessionService(mockDataStore, mockConfigurationService);
  }

  @Test
  void shouldCreateSessionItem() {
    String ipvSessionID = ipvSessionService.generateIpvSession();

    ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
        ArgumentCaptor.forClass(IpvSessionItem.class);
    verify(mockDataStore).create(ipvSessionItemArgumentCaptor.capture());
    assertNotNull(ipvSessionItemArgumentCaptor.getValue().getIpvSessionId());
    assertNotNull(ipvSessionItemArgumentCaptor.getValue().getCreationDateTime());

    assertEquals(ipvSessionItemArgumentCaptor.getValue().getIpvSessionId(), ipvSessionID);
  }
}
