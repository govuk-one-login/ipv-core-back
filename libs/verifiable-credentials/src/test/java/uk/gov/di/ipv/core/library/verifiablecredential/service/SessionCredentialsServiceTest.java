package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.CoiSubjourneyType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;

import java.time.Instant;
import java.util.HashMap;
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
import static uk.gov.di.ipv.core.library.domain.CriIdentifer.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.CriIdentifer.DCMAW;
import static uk.gov.di.ipv.core.library.domain.CriIdentifer.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.CriIdentifer.HMRC_KBV;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_DELETE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;

@ExtendWith(MockitoExtension.class)
class SessionCredentialsServiceTest {
    private static final String SESSION_ID = "ipv-session-id";
    private static final VerifiableCredential CREDENTIAL_1 = vcDrivingPermit();
    private static final VerifiableCredential CREDENTIAL_2 = vcVerificationM1a();
    private static final VerifiableCredential CREDENTIAL_3 = vcNinoSuccessful();
    private static final String USER_ID = "userId";
    private static final String CRI_ID_1 = "criId1";
    private static final String CRI_ID_2 = "criId2";
    private static final String CRI_ID_3 = "criId3";
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
                            SESSION_ID, CRI_ID_1, CREDENTIAL_1.getSignedJwt(), false, now);
            var item2 =
                    new SessionCredentialItem(
                            SESSION_ID,
                            CRI_ID_2,
                            CREDENTIAL_2.getSignedJwt(),
                            false,
                            now.plusSeconds(10));
            var item3 =
                    new SessionCredentialItem(
                            SESSION_ID, CRI_ID_3, CREDENTIAL_3.getSignedJwt(), true, null);

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
                            SESSION_ID, CRI_ID_1, CREDENTIAL_1.getSignedJwt(), false, null);

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
                    new SessionCredentialItem(SESSION_ID, CRI_ID_1, mockSignedJwt, false, null);
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
        void deleteSessionCredentialShouldThrowVerifiableCredentialExceptionIfProblemDeleting() {
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
            when(mockDataStore.getItemsBySortKeyPrefix(SESSION_ID, CRI_ID_1))
                    .thenReturn(List.of(sessionCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForCri(SESSION_ID, CRI_ID_1);

            verify(mockDataStore).getItemsBySortKeyPrefix(SESSION_ID, CRI_ID_1);
            verify(mockDataStore).delete(List.of(sessionCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForJourneyTypeShouldPersistAddressVcForNameChange()
                throws Exception {
            var addressVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", ADDRESS.getId(), new HashMap<>() {});
            var fraudVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD.getId(), new HashMap<>() {});

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(List.of(sessionFraudCredentialItem, sessionAddressCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForSubjourneyType(
                    SESSION_ID, CoiSubjourneyType.GIVEN_NAMES_ONLY);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore).delete(List.of(sessionFraudCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForJourneyTypeShouldDeleteAddressAndFraudForAddressChange()
                throws Exception {
            var addressVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", ADDRESS.getId(), new HashMap<>() {});
            var fraudVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD.getId(), new HashMap<>() {});

            var dcmawVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", DCMAW.getId(), new HashMap<>() {});

            var hmrcKbvVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", HMRC_KBV.getId(), new HashMap<>() {});

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionDcmawCredentialItem = dcmawVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionHmrcKbvCredentialItem = hmrcKbvVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem,
                                    sessionHmrcKbvCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForSubjourneyType(
                    SESSION_ID, CoiSubjourneyType.ADDRESS_ONLY);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore)
                    .delete(List.of(sessionFraudCredentialItem, sessionAddressCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForJourneyTypeShouldDeleteAllVcsForNameAndAddressChange()
                throws Exception {
            var addressVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", ADDRESS.getId(), new HashMap<>() {});
            var fraudVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD.getId(), new HashMap<>() {});

            var dcmawVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", DCMAW.getId(), new HashMap<>() {});

            var hmrcKbvVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", HMRC_KBV.getId(), new HashMap<>() {});

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionDcmawCredentialItem = dcmawVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionHmrcKbvCredentialItem = hmrcKbvVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem,
                                    sessionHmrcKbvCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForSubjourneyType(
                    SESSION_ID, CoiSubjourneyType.GIVEN_NAMES_AND_ADDRESS);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore)
                    .delete(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem,
                                    sessionHmrcKbvCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForJourneyTypeShouldDeleteAllVcsIfNullJourneyType()
                throws Exception {
            var addressVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", ADDRESS.getId(), new HashMap<>() {});
            var fraudVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", EXPERIAN_FRAUD.getId(), new HashMap<>() {});

            var dcmawVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", DCMAW.getId(), new HashMap<>() {});

            var hmrcKbvVc =
                    VerifiableCredentialGenerator.generateVerifiableCredential(
                            "userId", HMRC_KBV.getId(), new HashMap<>() {});

            var sessionFraudCredentialItem = fraudVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionAddressCredentialItem = addressVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionDcmawCredentialItem = dcmawVc.toSessionCredentialItem(SESSION_ID, true);
            var sessionHmrcKbvCredentialItem = hmrcKbvVc.toSessionCredentialItem(SESSION_ID, true);

            when(mockDataStore.getItems(SESSION_ID))
                    .thenReturn(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem,
                                    sessionHmrcKbvCredentialItem));

            sessionCredentialService.deleteSessionCredentialsForSubjourneyType(SESSION_ID, null);

            verify(mockDataStore).getItems(SESSION_ID);
            verify(mockDataStore)
                    .delete(
                            List.of(
                                    sessionFraudCredentialItem,
                                    sessionAddressCredentialItem,
                                    sessionDcmawCredentialItem,
                                    sessionHmrcKbvCredentialItem));
        }

        @Test
        void deleteSessionCredentialsForCriShouldThrowIfProblemGetting() {
            when(mockDataStore.getItemsBySortKeyPrefix(SESSION_ID, CRI_ID_1))
                    .thenThrow(new IllegalStateException());

            var verifiableCredentialException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () ->
                                    sessionCredentialService.deleteSessionCredentialsForCri(
                                            SESSION_ID, CRI_ID_1));

            assertEquals(
                    HTTPResponse.SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
            assertEquals(
                    FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
        }

        @Test
        void deleteSessionCredentialsForCriShouldThrowIfProblemDeleting() {
            when(mockDataStore.getItemsBySortKeyPrefix(SESSION_ID, CRI_ID_1)).thenReturn(List.of());
            when(mockDataStore.delete(any())).thenThrow(new IllegalStateException());

            var verifiableCredentialException =
                    assertThrows(
                            VerifiableCredentialException.class,
                            () ->
                                    sessionCredentialService.deleteSessionCredentialsForCri(
                                            SESSION_ID, CRI_ID_1));

            assertEquals(
                    HTTPResponse.SC_SERVER_ERROR, verifiableCredentialException.getResponseCode());
            assertEquals(
                    FAILED_TO_DELETE_CREDENTIAL, verifiableCredentialException.getErrorResponse());
        }
    }
}
