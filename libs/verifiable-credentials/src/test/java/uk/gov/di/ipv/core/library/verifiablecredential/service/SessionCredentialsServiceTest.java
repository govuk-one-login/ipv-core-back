package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.DataStoreException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SESSION_CREDENTIALS_TABLE_WRITES;
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
    @Mock private static ConfigService mockConfigService;
    @Captor private ArgumentCaptor<SessionCredentialItem> sessionCredentialItemArgumentCaptor;
    @Captor private ArgumentCaptor<String> ipvSessionIdArgumentCaptor;
    @Mock private DataStore<SessionCredentialItem> mockDataStore;
    @InjectMocks private SessionCredentialsService sessionCredentialService;

    @Nested
    class WritesWithFeatureFlagDisabled {
        @BeforeEach
        void setUp() {
            when(mockConfigService.enabled(SESSION_CREDENTIALS_TABLE_WRITES)).thenReturn(false);
        }

        @Test
        void persistCredentialsShouldNotCreateItemsInDataStore() throws Exception {
            List<VerifiableCredential> credentialsToStore =
                    List.of(CREDENTIAL_1, CREDENTIAL_2, CREDENTIAL_3);
            sessionCredentialService.persistCredentials(credentialsToStore, SESSION_ID, false);

            verify(mockDataStore, never()).create(any(), any());
        }
    }

    @Nested
    class WritesWithFeatureFlagEnabled {
        @BeforeEach
        void setUp() {
            when(mockConfigService.enabled(SESSION_CREDENTIALS_TABLE_WRITES)).thenReturn(true);
        }

        @Test
        void persistCredentialsShouldStoreAllCredentials() throws Exception {
            List<VerifiableCredential> credentialsToStore =
                    List.of(CREDENTIAL_1, CREDENTIAL_2, CREDENTIAL_3);
            sessionCredentialService.persistCredentials(credentialsToStore, SESSION_ID, false);

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
        void persistCredentialsShouldThrowVerifiableCredentialExceptionIfProblemStoring() {
            doThrow(IllegalStateException.class).when(mockDataStore).create(any(), any());

            assertThrows(
                    VerifiableCredentialException.class,
                    () ->
                            sessionCredentialService.persistCredentials(
                                    List.of(CREDENTIAL_1), SESSION_ID, false));
        }
    }

    @Nested
    class Deletes {
        @Test
        void deleteSessionCredentialsShouldClearAllCredentialsForCurrentSession() throws Exception {
            sessionCredentialService.deleteSessionCredentials(SESSION_ID);

            verify(mockDataStore).deleteAllByPartition(ipvSessionIdArgumentCaptor.capture());

            assertEquals(SESSION_ID, ipvSessionIdArgumentCaptor.getValue());
        }

        @Test
        void deleteSessionCredentialShouldThrowVerifiableCredentialExceptionIfProblemDeleting()
                throws Exception {
            doThrow(new DataStoreException("nope"))
                    .when(mockDataStore)
                    .deleteAllByPartition(SESSION_ID);

            var verifiableCredentialException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () -> sessionCredentialService.deleteSessionCredentials(SESSION_ID));

            assertEquals(
                    HTTPResponse.SC_SERVER_ERROR,
                    verifiableCredentialException.getHttpStatusCode());
            assertEquals(
                    FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
        }
    }
}