package uk.gov.di.ipv.core.calldcmawasynccri;

import com.amazonaws.services.lambda.runtime.Context;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.calldcmawasynccri.service.DcmawAsyncCriService;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_ASYNC_CRI;

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
                    .lambdaInput(Map.of("journeyType", "ipv"))
                    .build();
    public static final String JOURNEY_ENHANCED_VERIFICATION = "/journey/enhanced-verification";
    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private DcmawAsyncCriService mockDcmawAsyncCriService;
    @Mock private CriStoringService mockCriStoringService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private VerifiableCredentialResponse mockVerifiableCredentialResponse;
    @InjectMocks private CallDcmawAsyncCriHandler callDcmawAsyncCriHandler;

    @BeforeEach
    public void setUp() {
        mockIpvSessionItem.setIpvSessionId("a-session-id");
    }

    @Test
    void handleRequestShouldCallDcmawCriAndReturnJourneyNextIfNoBreachingCiReceived()
            throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialResponse.getUserId()).thenReturn(TEST_USER_ID);
        when(mockVerifiableCredentialResponse.getCredentialStatus())
                .thenReturn(VerifiableCredentialStatus.PENDING);
        when(mockDcmawAsyncCriService.startDcmawAsyncSession(
                        any(String.class),
                        any(ClientOAuthSessionItem.class),
                        any(IpvSessionItem.class)))
                .thenReturn(mockVerifiableCredentialResponse);

        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService)
                .storeCriResponse(
                        eq(input),
                        eq(DCMAW_ASYNC_CRI),
                        any(String.class),
                        eq(clientOAuthSessionItem));

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(mockIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfMissingIpvSessionId() {
        ProcessRequest inputWithoutSessionId = new ProcessRequest();

        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(inputWithoutSessionId, mockContext);

        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatus.SC_BAD_REQUEST, lambdaResult.get("statusCode"));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), lambdaResult.get("message"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfDcmawCriServiceThrows() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockDcmawAsyncCriService.startDcmawAsyncSession(any(), any(), any()))
                .thenThrow(new RuntimeException("Oh dear"));

        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(input, mockContext);

        assertEquals("/journey/error", lambdaResult.get("journey"));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
        assertEquals(
                ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getCode(), lambdaResult.get("code"));
        assertEquals(
                ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getMessage(),
                lambdaResult.get("message"));
    }

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfCiStoringServiceThrows() throws Exception {
        List<Exception> exceptionsToThrow =
                List.of(new SqsException("Oops"), new RuntimeException("Oops"));

        for (Exception e : exceptionsToThrow) {
            when(mockIpvSessionService.getIpvSession("a-session-id"))
                    .thenReturn(mockIpvSessionItem);
            when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
            when(mockVerifiableCredentialResponse.getUserId()).thenReturn(TEST_USER_ID);
            when(mockVerifiableCredentialResponse.getCredentialStatus())
                    .thenReturn(VerifiableCredentialStatus.PENDING);
            when(mockDcmawAsyncCriService.startDcmawAsyncSession(any(), any(), any()))
                    .thenReturn(mockVerifiableCredentialResponse);
            doThrow(e).when(mockCriStoringService).storeCriResponse(any(), any(), any(), any());

            Map<String, Object> lambdaResult =
                    callDcmawAsyncCriHandler.handleRequest(input, mockContext);

            assertEquals("/journey/error", lambdaResult.get("journey"));
            assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
            assertEquals(
                    ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getCode(),
                    lambdaResult.get("code"));
            assertEquals(
                    ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI.getMessage(),
                    lambdaResult.get("message"));
        }
    }
}
