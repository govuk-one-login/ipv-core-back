package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
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
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;

@ExtendWith(MockitoExtension.class)
class CallTicfCriHandlerTest {
    public static final String TEST_USER_ID = "a-user-id";
    public static final ClientOAuthSessionItem clientOAuthSessionItem =
            ClientOAuthSessionItem.builder()
                    .userId(TEST_USER_ID)
                    .govukSigninJourneyId("a-govuk-journey-id")
                    .build();
    private static final ProcessRequest input =
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
    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private TicfCriService mockTicfCriService;
    @Mock private CiMitService mockCiMitService;
    @Mock private CiMitUtilityService mockCiMitUtilityService;
    @Mock private CriStoringService mockCriStoringService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private VerifiableCredential mockVerifiableCredential;
    @InjectMocks private CallTicfCriHandler callTicfCriHandler;

    @BeforeEach
    public void setUp() {
        mockIpvSessionItem.setIpvSessionId("a-session-id");
    }

    @Test
    void handleRequestShouldCallTicfCriAndReturnJourneyNextIfNoBreachingCiReceived()
            throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, mockIpvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService)
                .storeVcs(
                        TICF.getId(),
                        "an-ip-address",
                        "device-information",
                        List.of(mockVerifiableCredential),
                        clientOAuthSessionItem,
                        mockIpvSessionItem);

        verify(mockCiMitService)
                .getContraIndicators(TEST_USER_ID, "a-govuk-journey-id", "an-ip-address");

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(mockIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnJourneyNextIfEmptyListReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, mockIpvSessionItem))
                .thenReturn(List.of());

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService, never()).storeVcs(any(), any(), any(), any(), any(), any());
        verify(mockCiMitService, never()).getContraIndicators(any(), any(), any());

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(mockIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnFailWithCiIfBreachingCiReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, mockIpvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));
        when(mockCiMitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.of(JOURNEY_FAIL_WITH_CI));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        assertEquals("/journey/fail-with-ci", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnEnhancedVerificationIfBreachingCiReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, mockIpvSessionItem))
                .thenReturn(List.of(mockVerifiableCredential));
        when(mockCiMitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.of(new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION)));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        assertEquals(JOURNEY_ENHANCED_VERIFICATION, lambdaResult.get("journey"));
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
    void handleRequestShouldReturnJourneyErrorResponseIfTicfCriServiceThrows() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockTicfCriService.getTicfVc(any(), any()))
                .thenThrow(new TicfCriServiceException("Oh dear"));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

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
            when(mockTicfCriService.getTicfVc(any(), any()))
                    .thenReturn(List.of(mockVerifiableCredential));
            doThrow(e)
                    .when(mockCriStoringService)
                    .storeVcs(any(), any(), any(), any(), any(), any());

            Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

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
                                        "storeVcs",
                                        String.class,
                                        String.class,
                                        String.class,
                                        List.class,
                                        ClientOAuthSessionItem.class,
                                        IpvSessionItem.class)
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

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfCiMitServiceThrows() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockTicfCriService.getTicfVc(any(), any()))
                .thenReturn(List.of(mockVerifiableCredential));
        when(mockCiMitService.getContraIndicators(any(), any(), any()))
                .thenThrow(new CiRetrievalException("Oh dear"));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(mockIpvSessionItem);
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
}
