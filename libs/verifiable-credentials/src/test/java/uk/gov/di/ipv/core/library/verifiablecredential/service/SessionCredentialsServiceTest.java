package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType;
import uk.gov.di.ipv.core.library.exceptions.BatchProcessingException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;

import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_DELETE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.ADDRESS_ONLY_CHANGE;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.NAME_ONLY_CHANGE;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianKbvM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoIdentityCheckSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.vcClaimFailedWithCis;

@ExtendWith(MockitoExtension.class)
class SessionCredentialsServiceTest {
    private static final String SESSION_ID = "ipv-session-id";
    private static final VerifiableCredential CREDENTIAL_1 = vcWebDrivingPermitDvaValid();
    private static final VerifiableCredential CREDENTIAL_2 = vcExperianKbvM1a();
    private static final VerifiableCredential CREDENTIAL_3 = vcNinoIdentityCheckSuccessful();
    private static final String USER_ID = "userId";
    @Captor private ArgumentCaptor<SessionCredentialItem> sessionCredentialItemArgumentCaptor;
    @Captor private ArgumentCaptor<String> ipvSessionIdArgumentCaptor;
    @Mock private DataStore<SessionCredentialItem> mockDataStore;
    @InjectMocks private SessionCredentialsService sessionCredentialService;

    @Nested
    class Writes {
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
    class Reads {
        @Test
        void getCredentialsShouldReturnAListOfVerifiableCredentials() throws Exception {
            var now = Instant.now();
            var item1 =
                    new SessionCredentialItem(
                            SESSION_ID,
                            CREDENTIAL_1.getCri(),
                            CREDENTIAL_1.getSignedJwt(),
                            false,
                            now);
            var item2 =
                    new SessionCredentialItem(
                            SESSION_ID,
                            CREDENTIAL_2.getCri(),
                            CREDENTIAL_2.getSignedJwt(),
                            false,
                            now.plusSeconds(10));
            var item3 =
                    new SessionCredentialItem(
                            SESSION_ID,
                            CREDENTIAL_3.getCri(),
                            CREDENTIAL_3.getSignedJwt(),
                            true,
                            null);

            when(mockDataStore.getItems(SESSION_ID)).thenReturn(List.of(item1, item2, item3));

            var retrievedVc = sessionCredentialService.getCredentials(SESSION_ID, USER_ID);

            assertEquals(
                    VerifiableCredential.fromSessionCredentialItem(item1, USER_ID),
                    retrievedVc.get(0));
            assertEquals(
                    VerifiableCredential.fromSessionCredentialItem(item2, USER_ID),
                    retrievedVc.get(1));
            assertEquals(
                    VerifiableCredential.fromSessionCredentialItem(item3, USER_ID),
                    retrievedVc.get(2));
        }

        @Test
        void getCredentialsShouldAllowFilteringByReceivedThisSession() throws Exception {
            var item1 =
                    new SessionCredentialItem(
                            SESSION_ID,
                            CREDENTIAL_1.getCri(),
                            CREDENTIAL_1.getSignedJwt(),
                            false,
                            null);

            when(mockDataStore.getItemsWithBooleanAttribute(
                            SESSION_ID, "receivedThisSession", true))
                    .thenReturn(List.of(item1));

            var retrievedVc = sessionCredentialService.getCredentials(SESSION_ID, USER_ID, true);

            assertEquals(
                    VerifiableCredential.fromSessionCredentialItem(item1, USER_ID),
                    retrievedVc.get(0));
        }

        @Test
        void
                getCredentialsShouldThrowVerifiableCredentialExceptionIfSessionStoreItemCanNotBeParsed() {
            SignedJWT mockSignedJwt = mock(SignedJWT.class);
            when(mockSignedJwt.serialize()).thenReturn("🫠");

            var sessionCredentialItem =
                    new SessionCredentialItem(
                            SESSION_ID, CREDENTIAL_1.getCri(), mockSignedJwt, false, null);
            when(mockDataStore.getItems(SESSION_ID)).thenReturn(List.of(sessionCredentialItem));

            var caughtException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () -> sessionCredentialService.getCredentials(SESSION_ID, USER_ID));

            assertEquals(FAILED_TO_PARSE_ISSUED_CREDENTIALS, caughtException.getErrorResponse());
        }

        @Test
        void getCredentialsShouldThrowVerifiableCredentialExceptionIfFetchingThrows() {
            when(mockDataStore.getItems(SESSION_ID)).thenThrow(new IllegalStateException());

            var caughtException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () -> sessionCredentialService.getCredentials(SESSION_ID, USER_ID));

            assertEquals(FAILED_TO_GET_CREDENTIAL, caughtException.getErrorResponse());
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
                throws BatchProcessingException {
            doThrow(new IllegalStateException())
                    .when(mockDataStore)
                    .deleteAllByPartition(SESSION_ID);

            var verifiableCredentialException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () -> sessionCredentialService.deleteSessionCredentials(SESSION_ID));

            assertEquals(
                    HTTPResponse.SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
            assertEquals(
                    FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
        }

        @Test
        void deleteSessionCredentialsForCriShouldDeleteAllCredentialsFromCriForSession()
                throws Exception {
            var sessionCredentialItem = new SessionCredentialItem();
            when(mockDataStore.getItemsBySortKeyPrefix(SESSION_ID, CREDENTIAL_1.getCri().getId()))
                    .thenReturn(List.of(sessionCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForCri(
                    SESSION_ID, CREDENTIAL_1.getCri());

            verify(mockDataStore)
                    .getItemsBySortKeyPrefix(SESSION_ID, CREDENTIAL_1.getCri().getId());
            verify(mockDataStore).delete(List.of(sessionCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForResetTypeShouldPersistAddressVcForNameChange()
                throws Exception {
            var addressVc =
                    generateVerifiableCredential("userId", ADDRESS, vcClaimFailedWithCis(null));
            var fraudVc =
                    generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD, vcClaimFailedWithCis(null));

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(List.of(sessionFraudCredentialItem, sessionAddressCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForResetType(
                    SESSION_ID, NAME_ONLY_CHANGE);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore).delete(List.of(sessionFraudCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForResetTypeShouldDeleteAddressAndFraudForAddressChange()
                throws Exception {
            var addressVc =
                    generateVerifiableCredential("userId", ADDRESS, vcClaimFailedWithCis(null));
            var fraudVc =
                    generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD, vcClaimFailedWithCis(null));

            var dcmawVc = generateVerifiableCredential("userId", DCMAW, vcClaimFailedWithCis(null));

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionDcmawCredentialItem = dcmawVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForResetType(
                    SESSION_ID, ADDRESS_ONLY_CHANGE);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore)
                    .delete(List.of(sessionFraudCredentialItem, sessionAddressCredentialItem));
        }

        @ParameterizedTest
        @EnumSource(names = {"ALL", "PENDING_F2F_ALL", "REINSTATE"})
        void deleteSessionCredentialsForResetTypeShouldDeleteAllVcs(
                SessionCredentialsResetType resetType) throws Exception {
            var addressVc =
                    generateVerifiableCredential("userId", ADDRESS, vcClaimFailedWithCis(null));
            var fraudVc =
                    generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD, vcClaimFailedWithCis(null));

            var dcmawVc = generateVerifiableCredential("userId", DCMAW, vcClaimFailedWithCis(null));

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionDcmawCredentialItem = dcmawVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForResetType(SESSION_ID, resetType);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore)
                    .delete(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForResetTypeShouldDeleteDcmawVcs() throws Exception {
            var addressVc =
                    generateVerifiableCredential("userId", ADDRESS, vcClaimFailedWithCis(null));
            var fraudVc =
                    generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD, vcClaimFailedWithCis(null));

            var dcmawVc = generateVerifiableCredential("userId", DCMAW, vcClaimFailedWithCis(null));

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionDcmawCredentialItem = dcmawVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForResetType(
                    SESSION_ID, SessionCredentialsResetType.DCMAW);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore).delete(List.of(sessionDcmawCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForCriShouldThrowIfProblemGetting() {
            when(mockDataStore.getItemsBySortKeyPrefix(SESSION_ID, CREDENTIAL_1.getCri().getId()))
                    .thenThrow(new IllegalStateException());

            var verifiableCredentialException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () ->
                                    sessionCredentialService.deleteSessionCredentialsForCri(
                                            SESSION_ID, CREDENTIAL_1.getCri()));

            assertEquals(
                    HTTPResponse.SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
            assertEquals(
                    FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
        }

        @Test
        void deleteSessionCredentialsForCriShouldThrowIfProblemDeleting()
                throws BatchProcessingException {
            when(mockDataStore.getItemsBySortKeyPrefix(SESSION_ID, CREDENTIAL_1.getCri().getId()))
                    .thenReturn(List.of());
            doThrow(new IllegalStateException()).when(mockDataStore).delete(any());

            var verifiableCredentialException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () ->
                                    sessionCredentialService.deleteSessionCredentialsForCri(
                                            SESSION_ID, CREDENTIAL_1.getCri()));

            assertEquals(
                    HTTPResponse.SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
            assertEquals(
                    FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
        }
    }
}
