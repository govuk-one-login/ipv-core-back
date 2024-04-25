package uk.gov.di.ipv.core.storeidentity;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionVot;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;

import static org.apache.http.HttpStatus.SC_BAD_REQUEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_STORE_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IDENTITY_STORED_PATH;

@ExtendWith(MockitoExtension.class)
class StoreIdentityHandlerTest {
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String CODE = "code";
    private static final String COMPONENT_ID = "https://component-id.example";
    private static final String GOVUK_JOURNEY_ID = "govuk-journey-id";
    private static final String IP_ADDRESS = "1.2.3.4";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "message";
    private static final String SESSION_ID = "session-id";
    private static final String STATUS_CODE = "statusCode";
    private static final String USER_ID = "user-id";
    private static final ProcessRequest PROCESS_REQUEST =
            ProcessRequest.processRequestBuilder()
                    .ipvSessionId(SESSION_ID)
                    .ipAddress(IP_ADDRESS)
                    .build();
    private static final List<VerifiableCredential> VCS =
            List.of(
                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                    EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                    M1A_ADDRESS_VC);
    private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Captor ArgumentCaptor<AuditEvent> auditEventCaptor;
    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private ClientOAuthSessionDetailsService mockClientOauthSessionDetailsService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private AuditService mockAuditService;
    @InjectMocks private StoreIdentityHandler storeIdentityHandler;

    @BeforeAll
    static void setUpBeforeAll() {
        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(USER_ID);
        clientOAuthSessionItem.setGovukSigninJourneyId(GOVUK_JOURNEY_ID);
    }

    @BeforeEach
    void setUpBeforeEach() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);
        ipvSessionItem.setVot(P2);

        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID)).thenReturn(VCS);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(COMPONENT_ID);
    }

    @Test
    void shouldReturnAnIdentityStoredJourney() throws Exception {
        var response = storeIdentityHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_IDENTITY_STORED_PATH, response.get(JOURNEY));
        verify(mockVerifiableCredentialService).storeIdentity(VCS, USER_ID);
    }

    @Test
    void shouldSendAuditEventWithVotExtensionWhenIdentityAchieved() throws Exception {
        storeIdentityHandler.handleRequest(PROCESS_REQUEST, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
        assertEquals(P2, ((AuditExtensionVot) auditEvent.getExtensions()).vot());
        assertEquals(COMPONENT_ID, auditEvent.getComponentId());
        assertEquals(
                new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS),
                auditEvent.getUser());
    }

    @Test
    void shouldSendAuditEventWithVotExtensionWhenIdentityIncomplete() throws Exception {
        ipvSessionItem.setVot(P0);

        storeIdentityHandler.handleRequest(PROCESS_REQUEST, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
        assertNull(((AuditExtensionVot) auditEvent.getExtensions()).vot());
        assertEquals(COMPONENT_ID, auditEvent.getComponentId());
        assertEquals(
                new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS),
                auditEvent.getUser());
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void shouldReturnAnErrorJourneyIfIpvSessionIdMissing() throws Exception {
        var processRequestWithMissingSessionId = ProcessRequest.processRequestBuilder().build();

        var response =
                storeIdentityHandler.handleRequest(processRequestWithMissingSessionId, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(SC_BAD_REQUEST, response.get(STATUS_CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getCode(), response.get(CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getMessage(), response.get(MESSAGE));
        verify(mockVerifiableCredentialService, never()).storeIdentity(any(), any());
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantFetchSessionCredentials() throws Exception {
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID))
                .thenThrow(new VerifiableCredentialException(418, FAILED_TO_GET_CREDENTIAL));

        var response = storeIdentityHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(418, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), response.get(MESSAGE));
        verify(mockVerifiableCredentialService, never()).storeIdentity(any(), any());
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantStoreIdentity() throws Exception {
        doThrow(new VerifiableCredentialException(418, FAILED_TO_STORE_IDENTITY))
                .when(mockVerifiableCredentialService)
                .storeIdentity(any(), any());

        var response = storeIdentityHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(418, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_STORE_IDENTITY.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_STORE_IDENTITY.getMessage(), response.get(MESSAGE));
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantSendAuditEvent() throws Exception {
        doThrow(new SqsException("oops"))
                .when(mockAuditService)
                .sendAuditEvent(any(AuditEvent.class));

        var response = storeIdentityHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(500, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_SEND_AUDIT_EVENT.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_SEND_AUDIT_EVENT.getMessage(), response.get(MESSAGE));
    }
}
