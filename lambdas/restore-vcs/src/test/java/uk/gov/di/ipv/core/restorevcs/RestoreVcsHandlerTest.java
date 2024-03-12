package uk.gov.di.ipv.core.restorevcs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.InputStream;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@ExtendWith(MockitoExtension.class)
class RestoreVcsHandlerTest {
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockVcDataStore;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private AuditService mockAuditService;
    @InjectMocks private RestoreVcsHandler restoreVcsHandler;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;

    @Test
    void shouldRestoreVc() throws Exception {
        // Arrange
        InputStream inputStream =
                RestoreVcsHandlerTest.class.getResourceAsStream("/testRestoreVcsRequest.json");
        String TEST_USER_ID = "urn:uuid:0369ce52-b72d-42f5-83d4-ab561fa01fd7";
        VcStoreItem testKbvVc =
                new VcStoreItem(
                        TEST_USER_ID,
                        "kbv",
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                        Instant.now(),
                        Instant.now());
        when(mockVcDataStore.getItem(TEST_USER_ID, "kbv")).thenReturn(testKbvVc);

        // Act
        restoreVcsHandler.handleRequest(inputStream, null, null);

        // Assert
        verify(mockVcDataStore).createIfNotExists(testKbvVc);
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_RESTORED, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());

        verify(mockVcDataStore).delete(TEST_USER_ID, "kbv");
    }
}
