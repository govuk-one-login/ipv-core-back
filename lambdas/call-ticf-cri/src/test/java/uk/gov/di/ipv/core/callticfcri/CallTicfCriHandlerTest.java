package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.AuditExtensionException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;

@ExtendWith(MockitoExtension.class)
class CallTicfCriHandlerTest {
    public static final String TEST_USER_ID = "a-user-id";
    public static final ClientOAuthSessionItem clientOAuthSessionItem =
            ClientOAuthSessionItem.builder()
                    .userId(TEST_USER_ID)
                    .govukSigninJourneyId("a-govuk-journey-id")
                    .build();
    public static List<String> VC_IN_STORE;
    public static String M1A_ADDRESS_VC;
    public static String M1A_EXPERIAN_FRAUD_VC;
    public static String M1B_DCMAW_VC;
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
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private TicfCriService mockTicfCriService;
    @Mock private CiMitService mockCiMitService;
    @Mock private CiMitUtilityService mockCiMitUtilityService;
    @Mock private CriStoringService mockCriStoringService;
    @Spy private IpvSessionItem spyIpvSessionItem;
    @Mock private SignedJWT mockSignedJwt;
    @InjectMocks private CallTicfCriHandler callTicfCriHandler;

    @BeforeAll
    static void setVcs() throws Exception {
        M1A_ADDRESS_VC = vcAddressM1a();
        M1A_EXPERIAN_FRAUD_VC = vcExperianFraudM1a();
        M1B_DCMAW_VC = vcDcmawM1b();
        VC_IN_STORE = List.of(M1B_DCMAW_VC, M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC);
    }

    @BeforeEach
    public void setUp() {
        spyIpvSessionItem.setIpvSessionId("a-session-id");
    }

    @Test
    void handleRequestShouldCallTicfCriAndReturnJourneyNextIfNoBreachingCiReceived()
            throws Exception {
        spyIpvSessionItem.setVcReceivedThisSession(VC_IN_STORE);

        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getIdentityCredentials(any())).thenReturn(VC_IN_STORE);
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, spyIpvSessionItem, VC_IN_STORE))
                .thenReturn(List.of(mockSignedJwt));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService)
                .storeVcs(
                        TICF_CRI,
                        "an-ip-address",
                        List.of(mockSignedJwt),
                        clientOAuthSessionItem,
                        spyIpvSessionItem);

        verify(mockCiMitService)
                .getContraIndicatorsVC(TEST_USER_ID, "a-govuk-journey-id", "an-ip-address");
        verify(mockVerifiableCredentialService, times(1)).getVcStoreItems(TEST_USER_ID);

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldOnlySendVcsReceivedInCurrentSession() throws Exception {
        spyIpvSessionItem.setVcReceivedThisSession(List.of(M1A_ADDRESS_VC));

        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getIdentityCredentials(any())).thenReturn(VC_IN_STORE);
        when(mockTicfCriService.getTicfVc(
                        clientOAuthSessionItem, spyIpvSessionItem, List.of(M1A_ADDRESS_VC)))
                .thenReturn(List.of(mockSignedJwt));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService)
                .storeVcs(
                        TICF_CRI,
                        "an-ip-address",
                        List.of(mockSignedJwt),
                        clientOAuthSessionItem,
                        spyIpvSessionItem);

        verify(mockCiMitService)
                .getContraIndicatorsVC(TEST_USER_ID, "a-govuk-journey-id", "an-ip-address");
        verify(mockVerifiableCredentialService, times(1)).getVcStoreItems(TEST_USER_ID);

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldSendNoVcsIfNonReceivedThisSession() throws Exception {
        spyIpvSessionItem.setVcReceivedThisSession(List.of());

        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getIdentityCredentials(any())).thenReturn(VC_IN_STORE);
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, spyIpvSessionItem, List.of()))
                .thenReturn(List.of(mockSignedJwt));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService)
                .storeVcs(
                        TICF_CRI,
                        "an-ip-address",
                        List.of(mockSignedJwt),
                        clientOAuthSessionItem,
                        spyIpvSessionItem);

        verify(mockCiMitService)
                .getContraIndicatorsVC(TEST_USER_ID, "a-govuk-journey-id", "an-ip-address");
        verify(mockVerifiableCredentialService, times(1)).getVcStoreItems(TEST_USER_ID);

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnJourneyNextIfEmptyListReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getIdentityCredentials(any()))
                .thenReturn(List.of(M1B_DCMAW_VC, M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC));
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, spyIpvSessionItem, List.of()))
                .thenReturn(List.of());

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        verify(mockCriStoringService, never()).storeVcs(any(), any(), any(), any(), any());
        verify(mockCiMitService, never()).getContraIndicatorsVC(any(), any(), any());

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/next", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnFailWithCiIfBreachingCiReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getIdentityCredentials(any())).thenReturn(List.of());
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, spyIpvSessionItem, List.of()))
                .thenReturn(List.of(mockSignedJwt));
        when(mockCiMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        InOrder inOrder = inOrder(spyIpvSessionItem, mockIpvSessionService);
        inOrder.verify(spyIpvSessionItem).setVot(Vot.P0);
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

        assertEquals("/journey/fail-with-ci", lambdaResult.get("journey"));
    }

    @Test
    void handleRequestShouldReturnEnhancedVerificationIfBreachingCiReceived() throws Exception {
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getIdentityCredentials(any())).thenReturn(List.of());
        when(mockTicfCriService.getTicfVc(clientOAuthSessionItem, spyIpvSessionItem, List.of()))
                .thenReturn(List.of(mockSignedJwt));
        when(mockCiMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(mockCiMitUtilityService.getCiMitigationJourneyStep(any()))
                .thenReturn(Optional.of(new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION)));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        InOrder inOrder = inOrder(spyIpvSessionItem, mockIpvSessionService);
        inOrder.verify(spyIpvSessionItem).setVot(Vot.P0);
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        inOrder.verifyNoMoreInteractions();

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
                        new AuditExtensionException(""),
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
        when(mockIpvSessionService.getIpvSession("a-session-id")).thenReturn(spyIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(new ClientOAuthSessionItem());
        when(mockTicfCriService.getTicfVc(any(), any(), any())).thenReturn(List.of(mockSignedJwt));
        when(mockCiMitService.getContraIndicatorsVC(any(), any(), any()))
                .thenThrow(new CiRetrievalException("Oh dear"));

        Map<String, Object> lambdaResult = callTicfCriHandler.handleRequest(input, mockContext);

        InOrder inOrder = inOrder(mockIpvSessionService);
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
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
