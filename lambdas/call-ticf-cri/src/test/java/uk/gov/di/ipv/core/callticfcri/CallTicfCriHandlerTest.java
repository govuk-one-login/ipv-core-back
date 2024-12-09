package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.callticfcri.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.callticfcri.service.TicfCriService;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.OPENID;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;

@ExtendWith(MockitoExtension.class)
class CallTicfCriHandlerTest {
    private static final String TEST_USER_ID = "a-user-id";
    private static final ClientOAuthSessionItem CLIENT_OAUTH_SESSION_ITEM =
            ClientOAuthSessionItem.builder()
                    .userId(TEST_USER_ID)
                    .govukSigninJourneyId("a-govuk-journey-id")
                    .scope(OPENID)
                    .build();
    private static final ProcessRequest INPUT =
            ProcessRequest.processRequestBuilder()
                    .ipvSessionId("a-session-id")
                    .ipAddress("an-ip-address")
                    .deviceInformation("device-information")
                    .clientOAuthSessionId("an-oauth-session-id")
                    .journey("a-journey")
                    .lambdaInput(Map.of("journeyType", "ipv"))
                    .build();
    private static final String JOURNEY_ENHANCED_VERIFICATION = "/journey/enhanced-verification";
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);

    @Spy private IpvSessionItem ipvSessionItem;
    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private TicfCriService mockTicfCriService;
    @Mock private CimitService mockCimitService;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @Mock private CriStoringService mockCriStoringService;
    @Mock private VerifiableCredential mockVerifiableCredential;
    @Mock private AuditService mockAuditService;
    @InjectMocks private CallTicfCriHandler callTicfCriHandler;

    @BeforeEach
    public void setUp() {
        ipvSessionItem.setIpvSessionId("a-session-id");
        ipvSessionItem.setVot(P2);
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void handleRequestShouldCallTicfCriAndReturnJourneyNextIfNoBreachingCiReceived()
            throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(CLIENT_OAUTH_SESSION_ITEM);
        when(mockTicfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        verify(mockCriStoringService)
                .storeVcs(
                        TICF,
                        "an-ip-address",
                        "device-information",
                        List.of(mockVerifiableCredential),
                        CLIENT_OAUTH_SESSION_ITEM,
                        ipvSessionItem,
                        List.of());

        verify(mockCimitService)
                .getContraIndicators(TEST_USER_ID, "a-govuk-journey-id", "an-ip-address");

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnJourneyNextIfEmptyListReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(CLIENT_OAUTH_SESSION_ITEM);
        when(mockTicfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem))
                .thenReturn(List.of());

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        verify(mockCriStoringService, never())
                .storeVcs(any(), any(), any(), any(), any(), any(), any());
        verify(mockCimitService, never()).getContraIndicators(any(), any(), any());

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnFailWithCiIfBreachingCiReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(CLIENT_OAUTH_SESSION_ITEM);
        when(mockTicfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.of(JOURNEY_FAIL_WITH_CI));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        InOrder inOrder = inOrder(ipvSessionItem, mockIpvSessionService);
        inOrder.verify(ipvSessionItem).setVot(P0);
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/fail-with-ci", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnEnhancedVerificationIfBreachingCiReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(CLIENT_OAUTH_SESSION_ITEM);
        when(mockTicfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.of(new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION)));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        InOrder inOrder = inOrder(ipvSessionItem, mockIpvSessionService);
        inOrder.verify(ipvSessionItem).setVot(P0);
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals(JOURNEY_ENHANCED_VERIFICATION, lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldSkipCiCheckIfReverificationJourney() throws Exception {
        var reverificationClientSessionItem =
                ClientOAuthSessionItem.builder().scope(REVERIFICATION).build();

        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(reverificationClientSessionItem);
        when(mockTicfCriService.getTicfVc(reverificationClientSessionItem, ipvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        assertEquals("/journey/next", lambdaResult.get("journey"));
        verify(mockCriStoringService)
                .storeVcs(
                        TICF,
                        "an-ip-address",
                        "device-information",
                        List.of(mockVerifiableCredential),
                        reverificationClientSessionItem,
                        ipvSessionItem,
                        List.of());
        verify(mockCimitService, never()).getContraIndicators(any(), any(), any());
    }

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfMissingIpvSessionId() {
        ProcessRequest inputWithoutSessionId = new ProcessRequest();

        Map<String, Object> lambdaResult =
                callTicfCriHandler.handleRequest(inputWithoutSessionId, mockContext);

        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatus.SC_BAD_REQUEST, lambdaResult.get("statusCode"));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), lambdaResult.get("message"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfMissingTargetVot() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(CLIENT_OAUTH_SESSION_ITEM);
        when(mockTicfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));
        ipvSessionItem.setTargetVot(null);
        ipvSessionItem.setVot(P0);

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
        assertEquals(ErrorResponse.MISSING_TARGET_VOT.getCode(), lambdaResult.get("code"));
        assertEquals(ErrorResponse.MISSING_TARGET_VOT.getMessage(), lambdaResult.get("message"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfTicfCriServiceThrows() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(CLIENT_OAUTH_SESSION_ITEM);
        when(mockTicfCriService.getTicfVc(any(), any()))
                .thenThrow(new TicfCriServiceException("Oh dear"));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
        assertEquals(
                ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getCode(),
                lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getMessage(),
                lambdaResult.get("message"));
    }

    private static Stream<Exception> ciStoringExceptions() {
        return Stream.of(
                new CiPutException("Oops"),
                new CiPostMitigationsException("Oops"),
                new VerifiableCredentialException(1, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL));
    }

    @ParameterizedTest
    @MethodSource("ciStoringExceptions")
    void handleRequestShouldReturnJourneyErrorResponseIfCiStoringServiceThrows(Exception e)
            throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockTicfCriService.getTicfVc(any(), any()))
                .thenReturn(List.of(mockVerifiableCredential));
        doThrow(e)
                .when(mockCriStoringService)
                .storeVcs(any(), any(), any(), any(), any(), any(), any());

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
        assertEquals(
                ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getCode(),
                lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getMessage(),
                lambdaResult.get("message"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfCimitServiceThrows() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(CLIENT_OAUTH_SESSION_ITEM);
        when(mockTicfCriService.getTicfVc(any(), any()))
                .thenReturn(List.of(mockVerifiableCredential));
        when(mockCimitService.getContraIndicators(any(), any(), any()))
                .thenThrow(new CiRetrievalException("Oh dear"));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(INPUT, mockContext);

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
        assertEquals(
                ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getCode(),
                lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getMessage(),
                lambdaResult.get("message"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(CallTicfCriHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> callTicfCriHandler.handleRequest(INPUT, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }
}
