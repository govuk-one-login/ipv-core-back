package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
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

import java.util.List;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_DELETE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;

@ExtendWith(MockitoExtension.class)
class SessionCredentialsServiceTest {
    private static final String SESSION_ID = "ipv-session-id";
    private static final VerifiableCredential CREDENTIAL_1 = vcDrivingPermit();
    private static final VerifiableCredential CREDENTIAL_2 = vcVerificationM1a();
    private static final VerifiableCredential CREDENTIAL_3 = vcNinoSuccessful();
    @Captor private ArgumentCaptor<SessionCredentialItem> sessionCredentialItemArgumentCaptor;
    @Captor private ArgumentCaptor<String> ipvSessionIdArgumentCaptor;
    @Mock private DataStore<SessionCredentialItem> mockDataStore;
    @InjectMocks private SessionCredentialsService sessionCredentialService;

    @Test
    void persistCredentialShouldCreateItemInDataStore() throws Exception {
        sessionCredentialService.persistCredential(CREDENTIAL_1, SESSION_ID, true);

        verify(mockDataStore)
                .create(
                        sessionCredentialItemArgumentCaptor.capture(),
                        eq(ConfigurationVariable.SESSION_CREDENTIALS_TTL));
        var capturedSessionCredentialItem = sessionCredentialItemArgumentCaptor.getValue();

        assertEquals(SESSION_ID, capturedSessionCredentialItem.getIpvSessionId());
        assertEquals(
                String.format("drivingLicence#%s", CREDENTIAL_1.getSignedJwt().getSignature()),
                capturedSessionCredentialItem.getSortKey());
        assertEquals(CREDENTIAL_1.getVcString(), capturedSessionCredentialItem.getCredential());
        assertTrue(capturedSessionCredentialItem.isReceivedThisSession());
    }

    @Test
    void persistCredentialShouldThrowVerifiableCredentialExceptionIfProblemStoring() {
        doThrow(IllegalStateException.class).when(mockDataStore).create(any(), any());

        assertThrows(
                VerifiableCredentialException.class,
                () -> sessionCredentialService.persistCredential(CREDENTIAL_1, SESSION_ID, false));
    }

    @Test
    void persistCredentialsShouldStoreAllCredentials() throws Exception {
        List<VerifiableCredential> credentialsToStore =
                List.of(CREDENTIAL_1, CREDENTIAL_2, CREDENTIAL_3);
        sessionCredentialService.persistCredentials(credentialsToStore, SESSION_ID);

        verify(mockDataStore, times(3))
                .create(
                        sessionCredentialItemArgumentCaptor.capture(),
                        eq(ConfigurationVariable.SESSION_CREDENTIALS_TTL));
        List<SessionCredentialItem> createdItems =
                sessionCredentialItemArgumentCaptor.getAllValues();

        IntStream.range(0, 3)
                .forEach(
                        i -> {
                            assertEquals(SESSION_ID, createdItems.get(i).getIpvSessionId());
                            assertEquals(
                                    credentialsToStore.get(i).getVcString(),
                                    createdItems.get(i).getCredential());
                            assertFalse(createdItems.get(i).isReceivedThisSession());
                        });
    }

    @Test
    void deleteSessionCredentialsShouldClearAllCredentialsForCurrentSession() throws Exception {
        sessionCredentialService.deleteSessionCredentials(SESSION_ID);

        verify(mockDataStore).delete(ipvSessionIdArgumentCaptor.capture());

        assertEquals(SESSION_ID, ipvSessionIdArgumentCaptor.getValue());
    }

    @Test
    void deleteSessionCredentialShouldThrowVerifiableCredentialExceptionIfProblemDeleting() {
        when(mockDataStore.delete(SESSION_ID)).thenThrow(new IllegalStateException());

        var verifiableCredentialException =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> sessionCredentialService.deleteSessionCredentials(SESSION_ID));

        assertEquals(
                HTTPResponse.SC_SERVER_ERROR, verifiableCredentialException.getHttpStatusCode());
        assertEquals(FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
    }
}
