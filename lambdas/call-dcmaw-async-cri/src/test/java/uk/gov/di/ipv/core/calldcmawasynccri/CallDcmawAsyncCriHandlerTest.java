package uk.gov.di.ipv.core.calldcmawasynccri;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.calldcmawasynccri.service.DcmawAsyncCriService;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.MobileAppJourneyType;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.ConfigServiceHelper;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;

@ExtendWith(MockitoExtension.class)
class CallDcmawAsyncCriHandlerTest {
    public static final String TEST_USER_ID = "a-user-id";
    public static final String TEST_OAUTH_STATE = "some_dummy_state_value";
    public static final ClientOAuthSessionItem clientOAuthSessionItem =
            ClientOAuthSessionItem.builder()
                    .userId(TEST_USER_ID)
                    .clientOAuthSessionId(TEST_OAUTH_STATE)
                    .govukSigninJourneyId("a-govuk-journey-id")
                    .build();
    private static final ProcessRequest input =
            ProcessRequest.processRequestBuilder()
                    .ipvSessionId("a-session-id")
                    .ipAddress("an-ip-address")
                    .clientOAuthSessionId("an-oauth-session-id")
                    .journey("a-journey")
                    .lambdaInput(Map.of("mobileAppJourneyType", "mam"))
                    .build();
    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private DcmawAsyncCriService mockDcmawAsyncCriService;
    @Mock private CriStoringService mockCriStoringService;
    @Mock private AuditService mockAuditService;
    private static final IpvSessionItem mockIpvSessionItem = new IpvSessionItem();
    @InjectMocks private CallDcmawAsyncCriHandler callDcmawAsyncCriHandler;

    @BeforeEach
    public void setUp() {
        mockIpvSessionItem.setIpvSessionId("a-session-id");

        ConfigServiceHelper.stubDefaultComponentIdConfig(mockConfigService, mockConfig);
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void handleRequestShouldCallDcmawAsyncCriAndReturnJourneyNextForValidResponse()
            throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(TEST_USER_ID)
                        .credentialStatus(VerifiableCredentialStatus.PENDING)
                        .build();
        when(mockDcmawAsyncCriService.startDcmawAsyncSession(
                        any(String.class),
                        eq(clientOAuthSessionItem),
                        eq(mockIpvSessionItem),
                        eq(MobileAppJourneyType.MAM)))
                .thenReturn(vcResponse);

        // Act
        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(input, mockContext);

        // Assert
        verify(mockCriStoringService)
                .recordCriResponse(
                        eq(input),
                        eq(DCMAW_ASYNC),
                        any(String.class),
                        eq(clientOAuthSessionItem),
                        eq(Collections.emptyList()));

        verify(mockIpvSessionService).updateIpvSession(mockIpvSessionItem);
        verify(mockDcmawAsyncCriService).sendAuditEventForAppHandoff(any(), any());

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void
            handleRequestShouldReturnJourneyErrorResponseAndRespectValuesInHttpResponseExceptionWithErrorBody() {
        // Arrange
        // By not having an IPV session ID we will cause the static methoed
        // RequestHelper.getIpvSessionId() to throw
        // a HttpResponseExceptionWithErrorBody
        ProcessRequest inputWithoutSessionId = new ProcessRequest();

        // Act
        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(inputWithoutSessionId, mockContext);

        // Assert
        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatusCode.BAD_REQUEST, lambdaResult.get("statusCode"));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), lambdaResult.get("message"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorIfResponseIsNotPending() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(TEST_USER_ID)
                        .credentialStatus(VerifiableCredentialStatus.CREATED)
                        .build();
        when(mockDcmawAsyncCriService.startDcmawAsyncSession(
                        any(String.class),
                        eq(clientOAuthSessionItem),
                        eq(mockIpvSessionItem),
                        eq(MobileAppJourneyType.MAM)))
                .thenReturn(vcResponse);

        // Act
        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(input, mockContext);

        // Assert
        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
        assertEquals(
                ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getCode(), lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getMessage(),
                lambdaResult.get("message"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorIfResponseIsUserIdDoesntMatch() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId("Wrong-user-id")
                        .credentialStatus(VerifiableCredentialStatus.PENDING)
                        .build();
        when(mockDcmawAsyncCriService.startDcmawAsyncSession(
                        any(String.class),
                        eq(clientOAuthSessionItem),
                        eq(mockIpvSessionItem),
                        eq(MobileAppJourneyType.MAM)))
                .thenReturn(vcResponse);

        // Act
        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(input, mockContext);

        // Assert
        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
        assertEquals(
                ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getCode(), lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getMessage(),
                lambdaResult.get("message"));
    }

    @Test
    void shouldLogRuntimeExceptions() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(CallDcmawAsyncCriHandler.class);

        // Act
        callDcmawAsyncCriHandler.handleRequest(input, mockContext);

        // Assert
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Error calling DCMAW Async CRI"));
        assertThat(logMessage, containsString("Test error"));
    }
}
