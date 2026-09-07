package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.junit.jupiter.api.BeforeEach;
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
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudNotExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
class StoreIdentityServiceTest {
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String COMPONENT_ID = "https://core-component.example";
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

    @Test
    void shouldSendAuditEventWithNullVotAndIdentityTypeExtensionWhenIdentityPendingWithFailedVot()
            throws Exception {
        // Arrange
        when(configService.getComponentId()).thenReturn("https://core-component.example");

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
        assertNull(((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).maxVot());
        assertEquals(
                CandidateIdentityType.PENDING,
                ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).identityType());
        assertEquals(COMPONENT_ID, auditEvent.getComponentId());
        assertEquals(testAuditEventUser, auditEvent.getUser());
        verify(evcsService, times(1)).storePendingIdentityWithPostVcs(any(), any(), any(), any());
    }

    private static Stream<Arguments> identityTypes() {
        return Stream.of(
                Arguments.of(CandidateIdentityType.NEW),
                Arguments.of(CandidateIdentityType.UPDATE),
                Arguments.of(CandidateIdentityType.EXISTING));
    }

    @ParameterizedTest
    @MethodSource("identityTypes")
    void shouldSuccessfullyStoreNewIdentityAndSiAndSendAuditEvent(
            CandidateIdentityType candidateIdentityType) throws Exception {
        // Arrange
        when(evcsService.storeStoredIdentityRecordAndVcs(any(), any(), any(), any(), any(), any()))
                .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(HttpStatusCode.ACCEPTED);
        when(configService.getComponentId()).thenReturn("https://core-component.example");

        // Act
        storeIdentityService.storeIdentity(
                USER_ID,
                VCS,
                List.of(),
                P2,
                STRONGEST_MATCHED_VOT,
                candidateIdentityType,
                sharedAuditEventParameters);

        // Assert
        verify(evcsService, times(1))
                .storeStoredIdentityRecordAndVcs(
                        USER_ID, GOVUK_JOURNEY_ID, VCS, List.of(), STRONGEST_MATCHED_VOT, P2);

        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
        assertEquals(
                P2, ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).maxVot());
        assertEquals(
                candidateIdentityType,
                ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).identityType());
        assertTrue(
                ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                        .sisRecordCreated());
        assertEquals(COMPONENT_ID, auditEvent.getComponentId());
        assertEquals(testAuditEventUser, auditEvent.getUser());
    }

    @Test
    void shouldSuccessfullyStorePendingIdentityWithPostPatchEndpointAndNotStoreSiAndSendAuditEvent()
            throws Exception {
        // Arrange
        when(configService.getComponentId()).thenReturn("https://core-component.example");

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
                .storePendingIdentityWithPostVcs(USER_ID, GOVUK_JOURNEY_ID, VCS, List.of());
        verify(evcsService, never())
                .storeStoredIdentityRecordAndVcs(any(), any(), any(), any(), any(), any());

        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
        assertEquals(
                P2, ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).maxVot());
        assertEquals(
                CandidateIdentityType.PENDING,
                ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).identityType());
        assertFalse(
                ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                        .sisRecordCreated());
        assertEquals(COMPONENT_ID, auditEvent.getComponentId());
        assertEquals(testAuditEventUser, auditEvent.getUser());
    }

    @Test
    void shouldThrowIfFailedToStoreVcsForPendingIdentity() throws Exception {
        // Arrange
        doThrow(EvcsServiceException.class)
                .when(evcsService)
                .storePendingIdentityWithPostVcs(USER_ID, GOVUK_JOURNEY_ID, VCS, List.of());

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
                                CandidateIdentityType.PENDING,
                                sharedAuditEventParameters));
    }

    @Test
    void shouldThrowIfFailedToStoreVcsAndSiObjectInOneTransaction() throws Exception {
        // Arrange
        doThrow(FailedToCreateStoredIdentityForEvcsException.class)
                .when(evcsService)
                .storeStoredIdentityRecordAndVcs(
                        USER_ID, GOVUK_JOURNEY_ID, VCS, List.of(), STRONGEST_MATCHED_VOT, P2);

        // Act/Assert
        assertThrows(
                FailedToCreateStoredIdentityForEvcsException.class,
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
}
