package uk.gov.di.ipv.core.processcandidateidentity.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCandidateIdentityType;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;

@ExtendWith(MockitoExtension.class)
class StoreIdentityServiceTest {
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String COMPONENT_ID = "https://component-id.example";
    private static final String GOVUK_JOURNEY_ID = "govuk-journey-id";
    private static final String IP_ADDRESS = "1.2.3.4";
    private static final String SESSION_ID = "session-id";
    private static final String USER_ID = "user-id";
    private static final String DEVICE_INFORMATION = "device-information";
    private static final String EVCS_ACCESS_TOKEN = "evcs-access-token";
    private static final List<VerifiableCredential> VCS =
            List.of(vcWebPassportSuccessful(), EXPIRED_M1A_EXPERIAN_FRAUD_VC, M1A_ADDRESS_VC);
    @Spy private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;
    private AuditEventUser testAuditEventUser;

    @Mock ConfigService configService;
    @Mock SessionCredentialsService sessionCredentialsService;
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

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .userId(USER_ID)
                        .govukSigninJourneyId(GOVUK_JOURNEY_ID)
                        .evcsAccessToken(EVCS_ACCESS_TOKEN)
                        .build();
    }

    @Nested
    class StoreIdentityServiceSuccessfulStoreTest {
        @BeforeEach
        void setUpEach() {
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
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    CandidateIdentityType.NEW,
                    DEVICE_INFORMATION,
                    VCS,
                    testAuditEventUser);

            // Assert
            verify(evcsService, times(1)).storeCompletedIdentity(anyString(), any(), any());
        }

        @Test
        void shouldSendAuditEventWithVotExtensionWhenIdentityAchieved() throws Exception {
            // Arrange
            VCS.stream()
                    .map(
                            credential -> {
                                if (credential.getCri().equals(EXPERIAN_FRAUD)) {
                                    credential.setMigrated(null);
                                } else {
                                    credential.setMigrated(Instant.now());
                                }
                                return credential;
                            })
                    .toList();

            // Act
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    CandidateIdentityType.NEW,
                    DEVICE_INFORMATION,
                    VCS,
                    testAuditEventUser);

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
            verify(evcsService, times(1)).storeCompletedIdentity(anyString(), any(), any());
        }

        @Test
        void shouldSendAuditEventWithVotAndIdentityTypeExtensionWhenIdentityUpdated()
                throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    CandidateIdentityType.UPDATE,
                    DEVICE_INFORMATION,
                    VCS,
                    testAuditEventUser);

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
            verify(evcsService, times(1)).storeCompletedIdentity(anyString(), any(), any());
        }

        @Test
        void shouldSendAuditEventWithVotAndIdentityTypeExtensionWhenIdentityIncomplete()
                throws Exception {
            // Arrange
            ipvSessionItem.setVot(P0);

            // Act
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    CandidateIdentityType.NEW,
                    DEVICE_INFORMATION,
                    VCS,
                    testAuditEventUser);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();

            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertNull(((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    CandidateIdentityType.NEW,
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(testAuditEventUser, auditEvent.getUser());
        }

        @Test
        void shouldStoreIdentityInEvcsAndSendAuditEventForPendingVc() throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    CandidateIdentityType.PENDING,
                    DEVICE_INFORMATION,
                    VCS,
                    testAuditEventUser);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();
            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertEquals(
                    P2, ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    CandidateIdentityType.PENDING,
                    ((AuditExtensionCandidateIdentityType) auditEvent.getExtensions())
                            .identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(testAuditEventUser, auditEvent.getUser());

            verify(evcsService, times(1))
                    .storePendingIdentity(
                            USER_ID, VCS, clientOAuthSessionItem.getEvcsAccessToken());
        }
    }

    @Test
    void shouldNotReturnAnErrorJourneyIfFailedAtEvcsIdentityStore_forPendingF2f() throws Exception {
        // Arrange
        doThrow(
                        new EvcsServiceException(
                                HTTPResponse.SC_SERVER_ERROR, FAILED_AT_EVCS_HTTP_REQUEST_SEND))
                .when(evcsService)
                .storePendingIdentity(USER_ID, VCS, clientOAuthSessionItem.getEvcsAccessToken());

        // Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        storeIdentityService.storeIdentity(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                CandidateIdentityType.PENDING,
                                DEVICE_INFORMATION,
                                VCS,
                                testAuditEventUser));
    }
}
