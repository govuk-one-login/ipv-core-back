package uk.gov.di.ipv.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.IpvSessionItem;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static uk.gov.di.ipv.service.ConfigurationService.IS_LOCAL;

@ExtendWith(SystemStubsExtension.class)
@ExtendWith(MockitoExtension.class)
class IpvSessionServiceTest {

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock private DataStore<IpvSessionItem> mockDataStore;

    @Mock private ConfigurationService mockConfigurationService;

    private IpvSessionService ipvSessionService;

    @BeforeEach
    void setUp() {
        ipvSessionService = new IpvSessionService(mockDataStore, mockConfigurationService);
    }

    @Test
    void noArgsConstructor() {
        environmentVariables.set(IS_LOCAL, "true");
        systemProperties.set(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");

        assertDoesNotThrow(() -> new IpvSessionService());
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
