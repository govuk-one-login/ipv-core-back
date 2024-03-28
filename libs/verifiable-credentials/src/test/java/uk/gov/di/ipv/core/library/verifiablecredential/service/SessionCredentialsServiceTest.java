package uk.gov.di.ipv.core.library.verifiablecredential.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;

@ExtendWith(MockitoExtension.class)
class SessionCredentialsServiceTest {
    public static final String SESSION_ID = "ipv-session-id";
    public static final VerifiableCredential CREDENTIAL = vcDrivingPermit();
    @Captor private ArgumentCaptor<SessionCredentialItem> sessionCredentialItemArgumentCaptor;
    @Mock private DataStore<SessionCredentialItem> mockDataStore;
    @InjectMocks private SessionCredentialsService sessionCredentialService;

    @Test
    void persistCredentialShouldCreateItemInDataStore() throws Exception {
        sessionCredentialService.persistCredential(CREDENTIAL, SESSION_ID, true);

        verify(mockDataStore)
                .create(
                        sessionCredentialItemArgumentCaptor.capture(),
                        eq(ConfigurationVariable.SESSION_CREDENTIALS_TTL));
        var capturedSessionCredentialItem = sessionCredentialItemArgumentCaptor.getValue();

        assertEquals(SESSION_ID, capturedSessionCredentialItem.getIpvSessionId());
        assertEquals(
                String.format("drivingLicence#%s", CREDENTIAL.getSignedJwt().getSignature()),
                capturedSessionCredentialItem.getSortKey());
        assertEquals(CREDENTIAL.getVcString(), capturedSessionCredentialItem.getCredential());
        assertTrue(capturedSessionCredentialItem.isReceivedThisSession());
    }

    @Test
    void persistCredentialShouldThrowVerifiableCredentialExceptionIfProblemStoring() {
        doThrow(IllegalStateException.class).when(mockDataStore).create(any(), any());

        assertThrows(
                VerifiableCredentialException.class,
                () -> sessionCredentialService.persistCredential(CREDENTIAL, SESSION_ID, false));
    }
}
