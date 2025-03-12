package uk.gov.di.ipv.core.storeidentity;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionIdentityType;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IDENTITY_STORED_PATH;

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
    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    private static final ProcessRequest PROCESS_REQUEST_FOR_COMPLETED_IDENTITY =
            ProcessRequest.processRequestBuilder()
                    .ipvSessionId(SESSION_ID)
                    .ipAddress(IP_ADDRESS)
                    .lambdaInput(new HashMap<>(Map.of("identityType", "new")))
                    .build();
    private static final ProcessRequest PROCESS_REQUEST_FOR_PENDING_IDENTITY =
            ProcessRequest.processRequestBuilder()
                    .ipvSessionId(SESSION_ID)
                    .ipAddress(IP_ADDRESS)
                    .lambdaInput(new HashMap<>(Map.of("identityType", "pending")))
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
    @Mock private AuditService mockAuditService;
    @Mock private EvcsService mockEvcsService;
    @InjectMocks private StoreIdentityHandler storeIdentityHandler;

    @BeforeAll
    static void setUpBeforeAll() {
        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(USER_ID);
        clientOAuthSessionItem.setGovukSigninJourneyId(GOVUK_JOURNEY_ID);
        clientOAuthSessionItem.setEvcsAccessToken(TEST_EVCS_ACCESS_TOKEN);
    }

    @BeforeEach
    void setUpBeforeEach() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);
        ipvSessionItem.setVot(P2);

        lenient().when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        lenient()
                .when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        lenient()
                .when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID))
                .thenReturn(VCS);
        lenient()
                .when(mockConfigService.getParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(COMPONENT_ID);
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturnAnIdentityStoredJourney() throws Exception {
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID)).thenReturn(VCS);

        var response =
                storeIdentityHandler.handleRequest(
                        PROCESS_REQUEST_FOR_COMPLETED_IDENTITY, mockContext);

        assertEquals(JOURNEY_IDENTITY_STORED_PATH, response.get(JOURNEY));
        verify(mockEvcsService).storeCompletedIdentity(USER_ID, VCS, TEST_EVCS_ACCESS_TOKEN);
    }

    @Test
    void shouldSendAuditEventWithVotExtensionWhenIdentityAchieved() throws Exception {
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID)).thenReturn(VCS);

        storeIdentityHandler.handleRequest(PROCESS_REQUEST_FOR_COMPLETED_IDENTITY, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
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
        verify(mockEvcsService).storeCompletedIdentity(USER_ID, VCS, TEST_EVCS_ACCESS_TOKEN);
    }

    @Test
    void shouldSendAuditEventWithVotAndIdentityTypeExtensionWhenIdentityUpdated() throws Exception {
        var updateReq =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(IP_ADDRESS)
                        .lambdaInput(new HashMap<>(Map.of("identityType", "update")))
                        .build();
        storeIdentityHandler.handleRequest(updateReq, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
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
        verify(mockEvcsService).storeCompletedIdentity(USER_ID, VCS, TEST_EVCS_ACCESS_TOKEN);
    }

    @Test
    void shouldSendAuditEventWithVotAndIdentityTypeExtensionWhenIdentityIncomplete() {
        ipvSessionItem.setVot(P0);

        storeIdentityHandler.handleRequest(PROCESS_REQUEST_FOR_COMPLETED_IDENTITY, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
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
    void shouldReturnErrorIfMissingIdentityTypeParameter() throws Exception {
        ProcessRequest missingReq =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(IP_ADDRESS)
                        .lambdaInput(new HashMap<>())
                        .build();

        var response = storeIdentityHandler.handleRequest(missingReq, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(HttpStatusCode.BAD_REQUEST, response.get(STATUS_CODE));
        assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getCode(), response.get(CODE));
        assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get(MESSAGE));
        verify(mockEvcsService, never()).storeCompletedIdentity(any(), any(), any());
        verify(mockEvcsService, never()).storePendingIdentity(any(), any(), any());
    }

    @Test
    void shouldReturnErrorIfInvalidIdentityTypeParameter() throws Exception {
        ProcessRequest invalidReq =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(IP_ADDRESS)
                        .lambdaInput(new HashMap<>(Map.of("identityType", "INVALID")))
                        .build();

        var response = storeIdentityHandler.handleRequest(invalidReq, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(HttpStatusCode.BAD_REQUEST, response.get(STATUS_CODE));
        assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getCode(), response.get(CODE));
        assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get(MESSAGE));
        verify(mockEvcsService, never()).storeCompletedIdentity(any(), any(), any());
        verify(mockEvcsService, never()).storePendingIdentity(any(), any(), any());
    }

    @Test
    void shouldReturnAnErrorJourneyIfIpvSessionIdMissing() throws Exception {
        var processRequestWithMissingSessionId = ProcessRequest.processRequestBuilder().build();

        var response =
                storeIdentityHandler.handleRequest(processRequestWithMissingSessionId, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(HttpStatusCode.BAD_REQUEST, response.get(STATUS_CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getCode(), response.get(CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getMessage(), response.get(MESSAGE));
        verify(mockEvcsService, never()).storeCompletedIdentity(any(), any(), any());
        verify(mockEvcsService, never()).storePendingIdentity(any(), any(), any());
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantFetchSessionCredentials() throws Exception {
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID))
                .thenThrow(new VerifiableCredentialException(418, FAILED_TO_GET_CREDENTIAL));

        var response =
                storeIdentityHandler.handleRequest(
                        PROCESS_REQUEST_FOR_COMPLETED_IDENTITY, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(418, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), response.get(MESSAGE));
        verify(mockEvcsService, never()).storeCompletedIdentity(any(), any(), any());
        verify(mockEvcsService, never()).storePendingIdentity(any(), any(), any());
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantStoreIdentity() throws Exception {
        doThrow(new EvcsServiceException(418, FAILED_TO_PARSE_EVCS_REQUEST_BODY))
                .when(mockEvcsService)
                .storeCompletedIdentity(USER_ID, VCS, TEST_EVCS_ACCESS_TOKEN);

        var response =
                storeIdentityHandler.handleRequest(
                        PROCESS_REQUEST_FOR_COMPLETED_IDENTITY, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(418, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_PARSE_EVCS_REQUEST_BODY.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_PARSE_EVCS_REQUEST_BODY.getMessage(), response.get(MESSAGE));
    }

    @Test
    void shouldStorePendingIdentityInEvcs() throws Exception {
        var response =
                storeIdentityHandler.handleRequest(
                        PROCESS_REQUEST_FOR_PENDING_IDENTITY, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertEquals(JOURNEY_IDENTITY_STORED_PATH, response.get(JOURNEY));
        assertEquals(IPV_IDENTITY_STORED, auditEvent.getEventName());
        assertEquals(P2, ((AuditExtensionIdentityType) auditEvent.getExtensions()).vot());
        assertEquals(
                IdentityType.PENDING,
                ((AuditExtensionIdentityType) auditEvent.getExtensions()).identityType());
        assertEquals(COMPONENT_ID, auditEvent.getComponentId());
        assertEquals(
                new AuditEventUser(USER_ID, SESSION_ID, GOVUK_JOURNEY_ID, IP_ADDRESS),
                auditEvent.getUser());
        verify(mockEvcsService).storePendingIdentity(USER_ID, VCS, TEST_EVCS_ACCESS_TOKEN);
    }

    @Test
    void shouldReturnAnErrorJourneyIfStoringPendingFailed() throws Exception {
        doThrow(
                        new EvcsServiceException(
                                HttpStatusCode.INTERNAL_SERVER_ERROR,
                                FAILED_AT_EVCS_HTTP_REQUEST_SEND))
                .when(mockEvcsService)
                .storePendingIdentity(USER_ID, VCS, TEST_EVCS_ACCESS_TOKEN);

        var response =
                storeIdentityHandler.handleRequest(
                        PROCESS_REQUEST_FOR_PENDING_IDENTITY, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.get(STATUS_CODE));
        assertEquals(FAILED_AT_EVCS_HTTP_REQUEST_SEND.getCode(), response.get(CODE));
        assertEquals(FAILED_AT_EVCS_HTTP_REQUEST_SEND.getMessage(), response.get(MESSAGE));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(StoreIdentityHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () ->
                                storeIdentityHandler.handleRequest(
                                        PROCESS_REQUEST_FOR_PENDING_IDENTITY, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }
}
