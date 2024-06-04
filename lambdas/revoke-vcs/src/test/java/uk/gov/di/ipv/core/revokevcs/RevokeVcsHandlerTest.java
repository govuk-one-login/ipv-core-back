package uk.gov.di.ipv.core.revokevcs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@ExtendWith(MockitoExtension.class)
class RevokeVcsHandlerTest {
    private final String TEST_USER_ID = "urn:uuid:0369ce52-b72d-42f5-83d4-ab561fa01fd7";
    @Mock private OutputStream outputStream;
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private AuditService mockAuditService;
    @InjectMocks private RevokeVcsHandler revokeVcsHandler;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;

    @Test
    void shouldRevokeVc() throws Exception {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        var testKbvVcStoreItem =
                new VcStoreItem(
                        TEST_USER_ID,
                        "kbv",
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                        Instant.now(),
                        Instant.now(),
                        Instant.now());
        when(mockDataStore.getItem(TEST_USER_ID, "kbv")).thenReturn(testKbvVcStoreItem);

        // Act
        revokeVcsHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockDataStore).create(testKbvVcStoreItem);
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_REVOKED, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());

        verify(mockDataStore).delete(TEST_USER_ID, "kbv");
    }

    @Test
    void shouldNotRevokeVcIfDoesNotExist()
            throws IOException, SqsException, CredentialParseException {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        when(mockDataStore.getItem(TEST_USER_ID, "kbv")).thenReturn(null);

        // Act
        revokeVcsHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockDataStore, times(0)).create(any(VcStoreItem.class));
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_REVOKED_FAILURE, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());
    }

    @Test
    void shouldHandleError() throws Exception {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        VcStoreItem testKbvVcStoreItem =
                new VcStoreItem(
                        TEST_USER_ID,
                        "kbv",
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                        Instant.now(),
                        Instant.now(),
                        Instant.now());
        when(mockDataStore.getItem(TEST_USER_ID, "kbv")).thenReturn(testKbvVcStoreItem);
        doThrow(new RuntimeException("Some error"))
                .when(mockDataStore)
                .create(any(VcStoreItem.class));

        // Act
        revokeVcsHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_REVOKED_FAILURE, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());
    }
}
