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
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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
    @Mock private CiMitService mockCiMitService;
    @Mock private CiMitUtilityService mockCiMitUtilityService;
    @Mock private CriStoringService mockCriStoringService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private VerifiableCredentialResponse mockVerifiableCredentialResponse;
    @InjectMocks private CallDcmawAsyncCriHandler callDcmawAsyncCriHandler;

    @BeforeEach
    public void setUp() {
        mockIpvSessionItem.setIpvSessionId("a-session-id");
    }

    // qq:DCC make these tests relevant
    @Test
    void handleRequestShouldCallTicfCriAndReturnJourneyNextIfNoBreachingCiReceived()
            throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockDcmawAsyncCriService.startDcmawAsyncSession(
                        TEST_OAUTH_STATE, clientOAuthSessionItem, mockIpvSessionItem))
                .thenReturn(mockVerifiableCredentialResponse);

        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService)
                .storeCriResponse(input, DCMAW_ASYNC_CRI, TEST_OAUTH_STATE, clientOAuthSessionItem);

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
    void handleRequestShouldReturnJourneyErrorResponseIfTicfCriServiceThrows() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockDcmawAsyncCriService.startDcmawAsyncSession(any(), any(), any()))
                .thenThrow(new Exception("Oh dear"));

        Map<String, Object> lambdaResult =
                callDcmawAsyncCriHandler.handleRequest(input, mockContext);

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
    void handleRequestShouldReturnJourneyErrorResponseIfCiStoringServiceThrows() throws Exception {
        List<Exception> exceptionsToThrow =
                List.of(
                        new SqsException("Oops"),
                        new CiPutException("Oops"),
                        new CiPostMitigationsException("Oops"),
                        new VerifiableCredentialException(1, ErrorResponse.INVALID_SESSION_ID));

        for (Exception e : exceptionsToThrow) {
            when(mockIpvSessionService.getIpvSession("a-session-id"))
                    .thenReturn(mockIpvSessionItem);
            when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(new ClientOAuthSessionItem());
            when(mockDcmawAsyncCriService.startDcmawAsyncSession(any(), any(), any()))
                    .thenReturn(mockVerifiableCredentialResponse);
            doThrow(e).when(mockCriStoringService).storeCriResponse(any(), any(), any(), any());

            Map<String, Object> lambdaResult =
                    callDcmawAsyncCriHandler.handleRequest(input, mockContext);

            assertEquals("/journey/error", lambdaResult.get("journey"));
            assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, lambdaResult.get("statusCode"));
            assertEquals(
                    ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getCode(),
                    lambdaResult.get("code"));
            assertEquals(
                    ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE.getMessage(),
                    lambdaResult.get("message"));
        }

        List<Class<?>> declaredExceptions =
                List.of(
                        CriStoringService.class
                                .getMethod(
                                        "storeCriResponse",
                                        ProcessRequest.class,
                                        String.class,
                                        String.class,
                                        ClientOAuthSessionItem.class)
                                .getExceptionTypes());

        // Checking to make sure we've tested all exceptions that can be thrown
        assertTrue(
                exceptionsToThrow.stream()
                        .allMatch(
                                exception ->
                                        declaredExceptions.contains(exception.getClass())
                                                || declaredExceptions.contains(
                                                        exception.getClass().getSuperclass())));
    }
}
