package uk.gov.di.ipv.core.revokevcs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RevokeVcsHandlerTest {
    private final String TEST_USER_ID = "urn:uuid:0369ce52-b72d-42f5-83d4-ab561fa01fd7";
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private RevokeVcsHandler revokeVcsHandler;

    @Test
    void shouldRevokeVc() throws IOException {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        VcStoreItem testKbvVc =
                new VcStoreItem(
                        TEST_USER_ID, "kbv", "test-credential", Instant.now(), Instant.now());
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, "kbv"))
                .thenReturn(testKbvVc);

        // Act
        revokeVcsHandler.handleRequest(inputStream, null, null);

        // Assert
        verify(mockDataStore).create(testKbvVc);
    }

    @Test
    void shouldNotRevokeVcIfDoesNotExist() throws IOException {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, "kbv")).thenReturn(null);

        // Act
        revokeVcsHandler.handleRequest(inputStream, null, null);

        // Assert
        verify(mockDataStore, times(0)).create(any());
    }
}
