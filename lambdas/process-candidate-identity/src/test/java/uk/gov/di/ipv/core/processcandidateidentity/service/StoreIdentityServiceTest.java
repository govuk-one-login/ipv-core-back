package uk.gov.di.ipv.core.processcandidateidentity.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCandidateIdentityType;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.ipv.core.processcandidateidentity.domain.SharedAuditEventParameters;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.STORED_IDENTITY_SERVICE;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudNotExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
class StoreIdentityServiceTest {
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String COMPONENT_ID = "https://component-id.example";
    private static final String GOVUK_JOURNEY_ID = "govuk-journey-id";
    private static final String IP_ADDRESS = "1.2.3.4";
    private static final String SESSION_ID = "session-id";
    private static final String USER_ID = "user-id";
    private static final String DEVICE_INFORMATION = "device-information";
    private static final List<VerifiableCredential> VCS =
            List.of(vcWebPassportSuccessful(), vcExperianFraudNotExpired(), vcAddressM1a());
    private static final VotMatchingResult.VotAndProfile STRONGEST_MATCHED_VOT =
            new VotMatchingResult.VotAndProfile(P2, Optional.of(M1A));
    @Spy private static IpvSessionItem ipvSessionItem;
    private AuditEventUser testAuditEventUser;
    private SharedAuditEventParameters sharedAuditEventParameters;

    @Mock HttpResponse<String> httpResponse;
    @Mock ConfigService configService;
    @Mock AuditService auditService;
    @Mock EvcsService evcsService;
    @InjectMocks StoreIdentityService storeIdentityService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @BeforeEach
    void setUpEach() {
        testAuditEventUser = new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS);
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);
        ipvSessionItem.setVot(P2);

        sharedAuditEventParameters =
                new SharedAuditEventParameters(testAuditEventUser, DEVICE_INFORMATION);
    }

    @Nested
    class StoreIdentityServiceSuccessfulStoreTest {
        @BeforeEach
        void setUp() {
            when(configService.getParameter(ConfigurationVariable.COMPONENT_ID))
                    .thenReturn(COMPONENT_ID);
        }

        @Test
        void shouldSuccessfullyStoreIdentityWhenEvcsWriteEnabled() throws Exception {
            // Arrange
            VCS.forEach(
                    credential -> {
                        if (credential.getCri().equals(EXPERIAN_FRAUD)) {
                            credential.setMigrated(null);
                        } else {
                            credential.setMigrated(Instant.now());
                        }
                    });

            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P2,
                    STRONGEST_MATCHED_VOT,
                    CandidateIdentityType.NEW,
                    sharedAuditEventParameters);

            // Assert
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), false);
        }

        @Test
        void shouldSendAuditEventWithVotExtensionWhenIdentityAchieved() throws Exception {
            // Arrange
            var testVcs =
                    VCS.stream()
                            .peek(
                                    credential -> {
                                        if (credential.getCri().equals(EXPERIAN_FRAUD)) {
                                            credential.setMigrated(null);
                                        } else {
                                            credential.setMigrated(Instant.now());
                                        }
                                    })
                            .toList();

            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    testVcs,
                    List.of(),
                    P2,
                    STRONGEST_MATCHED_VOT,
                    CandidateIdentityType.NEW,
                    sharedAuditEventParameters);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();

            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertEquals(
                    P2, ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    CandidateIdentityType.NEW,
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(testAuditEventUser, auditEvent.getUser());
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(any(), any(), any(), anyBoolean());
        }

        @Test
        void shouldSendAuditEventWithVotAndIdentityTypeExtensionWhenIdentityUpdated()
                throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P2,
                    STRONGEST_MATCHED_VOT,
                    CandidateIdentityType.UPDATE,
                    sharedAuditEventParameters);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();

            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertEquals(
                    P2, ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    CandidateIdentityType.UPDATE,
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(testAuditEventUser, auditEvent.getUser());
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(any(), any(), any(), anyBoolean());
        }

        @Test
        void shouldStoreIdentityInEvcsAndSendAuditEventForPendingVc() throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P0,
                    null,
                    CandidateIdentityType.PENDING,
                    sharedAuditEventParameters);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();
            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertNull(((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    CandidateIdentityType.PENDING,
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(testAuditEventUser, auditEvent.getUser());

            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), true);
        }

        @Test
        void
                shouldSendAuditEventWithNullVotAndIdentityTypeExtensionWhenIdentityPendingWithFailedVot()
                        throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P0,
                    null,
                    CandidateIdentityType.PENDING,
                    sharedAuditEventParameters);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();

            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertNull(((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    CandidateIdentityType.PENDING,
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(testAuditEventUser, auditEvent.getUser());
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(any(), any(), any(), anyBoolean());
        }
    }

    @Test
    void shouldThrowIfEvcsFailsToStorePendingIdentity() throws Exception {
        // Arrange
        doThrow(
                        new EvcsServiceException(
                                HTTPResponse.SC_SERVER_ERROR, FAILED_AT_EVCS_HTTP_REQUEST_SEND))
                .when(evcsService)
                .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), true);

        // Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        storeIdentityService.storeIdentity(
                                USER_ID,
                                VCS,
                                List.of(),
                                P0,
                                null,
                                CandidateIdentityType.PENDING,
                                sharedAuditEventParameters));
    }

    @Nested
    class StoreIdentityWithPut {
        @BeforeEach
        void setUp() {
            when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
        }

        @Test
        void shouldStoreStoredIdentityRecordForCompletedIdentity() throws Exception {
            // Arrange
            when(evcsService.storeStoredIdentityRecord(any(), any(), any(), any()))
                    .thenReturn(httpResponse);
            when(httpResponse.statusCode()).thenReturn(HttpStatusCode.ACCEPTED);

            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P2,
                    STRONGEST_MATCHED_VOT,
                    CandidateIdentityType.NEW,
                    sharedAuditEventParameters);

            // Assert
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), false);
            verify(evcsService, times(1))
                    .storeStoredIdentityRecord(USER_ID, VCS, STRONGEST_MATCHED_VOT, P2);
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());

            var auditEvent = auditEventCaptor.getValue();
            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertTrue(
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .sisRecordCreated());
        }

        @Test
        void shouldNotStoreStoredIdentityRecordForPendingIdentity() throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P2,
                    STRONGEST_MATCHED_VOT,
                    CandidateIdentityType.PENDING,
                    sharedAuditEventParameters);

            // Assert
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), true);
            verify(evcsService, times(0)).storeStoredIdentityRecord(any(), any(), any(), any());
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());

            var auditEvent = auditEventCaptor.getValue();
            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertFalse(
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .sisRecordCreated());
        }

        private static Stream<Arguments> provideStoreStoredIdentityRecordExceptions() {
            return Stream.of(
                    Arguments.of(
                            new FailedToCreateStoredIdentityForEvcsException(
                                    "could not create si record")),
                    Arguments.of(
                            new EvcsServiceException(
                                    SC_SERVER_ERROR,
                                    ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY)));
        }

        @ParameterizedTest
        @MethodSource("provideStoreStoredIdentityRecordExceptions")
        void shouldContinueIfStoreStoredIdentityRecordFails(Throwable exception) throws Exception {
            // Arrange
            when(evcsService.storeStoredIdentityRecord(any(), any(), any(), any()))
                    .thenThrow(exception);

            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P2,
                    STRONGEST_MATCHED_VOT,
                    CandidateIdentityType.NEW,
                    sharedAuditEventParameters);

            // Assert
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), false);
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());

            var auditEvent = auditEventCaptor.getValue();
            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertFalse(
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .sisRecordCreated());
        }

        @Test
        void
                shouldSetSisRecordCreatedToFalseIfNonHttpResponseReturnedFromStoreStoredIdentityRecord()
                        throws Exception {
            // Arrange
            when(evcsService.storeStoredIdentityRecord(any(), any(), any(), any()))
                    .thenReturn(httpResponse);
            when(httpResponse.statusCode()).thenReturn(HttpStatusCode.FORBIDDEN);

            // Act
            storeIdentityService.storeIdentity(
                    USER_ID,
                    VCS,
                    List.of(),
                    P2,
                    STRONGEST_MATCHED_VOT,
                    CandidateIdentityType.NEW,
                    sharedAuditEventParameters);

            // Assert
            verify(evcsService, times(1))
                    .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), false);
            verify(evcsService, times(1))
                    .storeStoredIdentityRecord(USER_ID, VCS, STRONGEST_MATCHED_VOT, P2);
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());

            var auditEvent = auditEventCaptor.getValue();
            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertFalse(
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .sisRecordCreated());
        }
    }

    @Test
    void shouldThrowIfStoreCompletedOrPendingIdentityWithPostMethodFails() throws Exception {
        // Arrange
        doThrow(EvcsServiceException.class)
                .when(evcsService)
                .storeCompletedOrPendingIdentityWithPost(USER_ID, VCS, List.of(), false);

        // Act/Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        storeIdentityService.storeIdentity(
                                USER_ID,
                                VCS,
                                List.of(),
                                P2,
                                STRONGEST_MATCHED_VOT,
                                CandidateIdentityType.NEW,
                                sharedAuditEventParameters));
    }

    @Test
    void shouldSetSisRecordCreatedFlagToFalseWhenFeatureFlagIsDisabled()
            throws EvcsServiceException {
        // arrange
        when(configService.enabled(CoreFeatureFlag.STORED_IDENTITY_SERVICE)).thenReturn(false);

        // act
        storeIdentityService.storeIdentity(
                USER_ID,
                VCS,
                List.of(),
                P1,
                STRONGEST_MATCHED_VOT,
                CandidateIdentityType.NEW,
                sharedAuditEventParameters);

        // assert
        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertFalse(
                ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                        .sisRecordCreated());
    }
}
