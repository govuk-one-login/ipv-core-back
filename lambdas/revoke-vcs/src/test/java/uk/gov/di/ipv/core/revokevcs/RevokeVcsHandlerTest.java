package uk.gov.di.ipv.core.revokevcs;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
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
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportNonDcmawSuccessful;

@ExtendWith(MockitoExtension.class)
class RevokeVcsHandlerTest {
    private final String TEST_USER_ID = "urn:uuid:0369ce52-b72d-42f5-83d4-ab561fa01fd7";
    private static String M1A_PASSPORT_VC;
    @Mock private OutputStream outputStream;
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private AuditService mockAuditService;
    @InjectMocks private RevokeVcsHandler revokeVcsHandler;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;

    @BeforeAll
    static void setup() throws Exception {
        M1A_PASSPORT_VC = vcPassportNonDcmawSuccessful();
    }

    @Test
    void shouldRevokeVc() throws IOException, SqsException {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        VcStoreItem testKbvVc =
                new VcStoreItem(TEST_USER_ID, "kbv", M1A_PASSPORT_VC, Instant.now(), Instant.now());
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, "kbv"))
                .thenReturn(testKbvVc);

        // Act
        revokeVcsHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockDataStore).create(testKbvVc);
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_REVOKED, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());

        verify(mockVerifiableCredentialService).deleteVcStoreItem(TEST_USER_ID, "kbv");
    }

    @Test
    void shouldNotRevokeVcIfDoesNotExist() throws IOException, SqsException {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, "kbv")).thenReturn(null);

        // Act
        revokeVcsHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockDataStore, times(0)).create(any());
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_REVOKED_FAILURE, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());
    }

    @Test
    void shouldHandleError() throws IOException, SqsException {
        // Arrange
        InputStream inputStream =
                RevokeVcsHandlerTest.class.getResourceAsStream("/testRevokeVcsRequest.json");
        VcStoreItem testKbvVc =
                new VcStoreItem(TEST_USER_ID, "kbv", M1A_PASSPORT_VC, Instant.now(), Instant.now());
        when(mockVerifiableCredentialService.getVcStoreItem(TEST_USER_ID, "kbv"))
                .thenReturn(testKbvVc);
        doThrow(new RuntimeException("Some error")).when(mockDataStore).create(any());

        // Act
        revokeVcsHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_REVOKED_FAILURE, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());
    }
}
