package uk.gov.di.ipv.core.restorevcs;

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
import uk.gov.di.ipv.core.library.exceptions.CredentialAlreadyExistsException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportNonDcmawSuccessful;

@ExtendWith(MockitoExtension.class)
class RestoreVcsHandlerTest {
    private static String M1A_PASSPORT_VC;
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private AuditService mockAuditService;
    @InjectMocks private RestoreVcsHandler restoreVcsHandler;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;

    @BeforeAll
    static void setup() throws Exception {
        M1A_PASSPORT_VC = vcPassportNonDcmawSuccessful();
    }

    @Test
    void shouldRestoreVc()
            throws IOException, SqsException, VerifiableCredentialException,
                    CredentialAlreadyExistsException {
        // Arrange
        InputStream inputStream =
                RestoreVcsHandlerTest.class.getResourceAsStream("/testRestoreVcsRequest.json");
        String TEST_USER_ID = "urn:uuid:0369ce52-b72d-42f5-83d4-ab561fa01fd7";
        VcStoreItem testKbvVc =
                new VcStoreItem(TEST_USER_ID, "kbv", M1A_PASSPORT_VC, Instant.now(), Instant.now());
        when(mockDataStore.getItem(TEST_USER_ID, "kbv")).thenReturn(testKbvVc);

        // Act
        restoreVcsHandler.handleRequest(inputStream, null, null);

        // Assert
        verify(mockVerifiableCredentialService)
                .persistUserCredentialsIfNotExists(any(), eq("kbv"), eq(TEST_USER_ID));
        verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());

        var auditEvent = auditEventArgumentCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_VC_RESTORED, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());

        verify(mockDataStore).delete(TEST_USER_ID, "kbv");
    }
}
