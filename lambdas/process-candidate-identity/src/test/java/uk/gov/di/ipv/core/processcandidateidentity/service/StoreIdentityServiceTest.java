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
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionIdentityType;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

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
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

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
            List.of(
                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                    EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                    M1A_ADDRESS_VC);
    @Spy private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Mock ConfigService configService;
    @Mock SessionCredentialsService sessionCredentialsService;
    @Mock VerifiableCredentialService verifiableCredentialService;
    @Mock AuditService auditService;
    @Mock EvcsService evcsService;
    @InjectMocks StoreIdentityService storeIdentityService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @BeforeEach
    void setUpEach() {
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
                    IdentityType.NEW,
                    DEVICE_INFORMATION,
                    IP_ADDRESS,
                    VCS);

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
                    IdentityType.NEW,
                    DEVICE_INFORMATION,
                    IP_ADDRESS,
                    VCS);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();

            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertEquals(P2, ((AuditExtensionIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    IdentityType.NEW,
                    ((AuditExtensionIdentityType) auditEvent.getExtensions()).identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(
                    new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS),
                    auditEvent.getUser());
            verify(evcsService, times(1)).storeCompletedIdentity(anyString(), any(), any());
        }

        @Test
        void shouldSendAuditEventWithVotAndIdentityTypeExtensionWhenIdentityUpdated()
                throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    IdentityType.UPDATE,
                    DEVICE_INFORMATION,
                    IP_ADDRESS,
                    VCS);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();

            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertEquals(P2, ((AuditExtensionIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    IdentityType.UPDATE,
                    ((AuditExtensionIdentityType) auditEvent.getExtensions()).identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(
                    new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS),
                    auditEvent.getUser());
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
                    IdentityType.NEW,
                    DEVICE_INFORMATION,
                    IP_ADDRESS,
                    VCS);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();

            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertNull(((AuditExtensionIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    IdentityType.NEW,
                    ((AuditExtensionIdentityType) auditEvent.getExtensions()).identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(
                    new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS),
                    auditEvent.getUser());
        }

        @Test
        void shouldStoreIdentityInEvcsAndSendAuditEventForPendingVc() throws Exception {
            // Act
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    IdentityType.PENDING,
                    DEVICE_INFORMATION,
                    IP_ADDRESS,
                    VCS);

            // Assert
            verify(auditService).sendAuditEvent(auditEventCaptor.capture());
            var auditEvent = auditEventCaptor.getValue();
            assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
            assertEquals(P2, ((AuditExtensionIdentityType) auditEvent.getExtensions()).vot());
            assertEquals(
                    IdentityType.PENDING,
                    ((AuditExtensionIdentityType) auditEvent.getExtensions()).identityType());
            assertEquals(COMPONENT_ID, auditEvent.getComponentId());
            assertEquals(
                    new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS),
                    auditEvent.getUser());

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
                                IdentityType.PENDING,
                                DEVICE_INFORMATION,
                                IP_ADDRESS,
                                VCS));
    }
}
