package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;

@ExtendWith(MockitoExtension.class)
class CallTicfCriHandlerTest {
    public static final ClientOAuthSessionItem clientOAuthSessionItem =
            ClientOAuthSessionItem.builder()
                    .userId("a-user-id")
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

    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private TicfCriService mockTicfCriService;
    @Mock private CiMitService mockCiMitService;
    @Mock private CiMitUtilityService mockCiMitUtilityService;
    @Mock private CriStoringService mockCriStoringService;
    @Spy private IpvSessionItem spyIpvSessionItem;
    @Mock private SignedJWT mockSignedJwt;
    @InjectMocks private CallTicfCriHandler callTicfCriHandler;

    @Test
    void handleRequestShouldCallTicfCriAndReturnJourneyNextIfNoBreachingCiReceived()
            throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getUserIssuedCredentials((List<VcStoreItem>) any()))
                .thenReturn(List.of("a-vc"));
        when(mockTicfCriService.getTicfVc(
                        clientOAuthSessionItem, spyIpvSessionItem, List.of("a-vc")))
                .thenReturn(List.of(mockSignedJwt));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService)
                .storeVcs(
                        TICF_CRI,
                        "an-ip-address",
                        "a-session-id",
                        List.of(mockSignedJwt),
                        clientOAuthSessionItem);

        verify(mockCiMitService)
                .getContraIndicatorsVC("a-user-id", "a-govuk-journey-id", "an-ip-address");

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldNotSendVCsInRequestIfReuseJourney() throws Exception {
        ProcessRequest reuseJourneyInput =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId("a-session-id")
                        .ipAddress("an-ip-address")
                        .clientOAuthSessionId("an-oauth-session-id")
                        .journey("a-journey")
                        .lambdaInput(Map.of("journeyType", "reuse"))
                        .build();
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, spyIpvSessionItem, List.of()))
                .thenReturn(List.of(mockSignedJwt));

        Map<String, Object> lambdaResult =
                callTicfCriHandler.handleRequest(reuseJourneyInput, mockContext);

        verify(mockTicfCriService).getTicfVc(clientOAuthSessionItem, spyIpvSessionItem, List.of());

        verify(mockCriStoringService)
                .storeVcs(
                        TICF_CRI,
                        "an-ip-address",
                        "a-session-id",
                        List.of(mockSignedJwt),
                        clientOAuthSessionItem);

        verify(mockCiMitService)
                .getContraIndicatorsVC("a-user-id", "a-govuk-journey-id", "an-ip-address");

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnJourneyNextIfEmptyListReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getUserIssuedCredentials((List<VcStoreItem>) any()))
                .thenReturn(List.of("a-vc"));
        when(mockTicfCriService.getTicfVc(
                        clientOAuthSessionItem, spyIpvSessionItem, List.of("a-vc")))
                .thenReturn(List.of());

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService, never()).storeVcs(any(), any(), any(), any(), any());
        verify(mockCiMitService, never()).getContraIndicatorsVC(any(), any(), any());

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnFailWithCiIfBreachingCiReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getUserIssuedCredentials((List<VcStoreItem>) any()))
                .thenReturn(List.of("a-vc"));
        when(mockTicfCriService.getTicfVc(
                        clientOAuthSessionItem, spyIpvSessionItem, List.of("a-vc")))
                .thenReturn(List.of(mockSignedJwt));
        when(mockCiMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        InOrder inOrder = inOrder(spyIpvSessionItem, mockIpvSessionService);
        inOrder.verify(spyIpvSessionItem).setVot("P0");
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/fail-with-ci", lambdaResult.get("journey"));
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
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockTicfCriService.getTicfVc(any(), any(), any()))
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
                        new ParseException("Oops", 1),
                        new JsonProcessingException("") {},
                        new CiPutException("Oops"),
                        new CiPostMitigationsException("Oops"),
                        new VerifiableCredentialException(1, ErrorResponse.INVALID_SESSION_ID));

        for (Exception e : exceptionsToThrow) {
            when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
            when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(new ClientOAuthSessionItem());
            when(mockTicfCriService.getTicfVc(any(), any(), any()))
                    .thenReturn(List.of(mockSignedJwt));
            doThrow(e).when(mockCriStoringService).storeVcs(any(), any(), any(), any(), any());

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

    @Test
    void handleRequestShouldReturnJourneyErrorResponseIfCiMitServiceThrows() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockTicfCriService.getTicfVc(any(), any(), any())).thenReturn(List.of(mockSignedJwt));
        when(mockCiMitService.getContraIndicatorsVC(any(), any(), any()))
                .thenThrow(new CiRetrievalException("Oh dear"));

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
}
