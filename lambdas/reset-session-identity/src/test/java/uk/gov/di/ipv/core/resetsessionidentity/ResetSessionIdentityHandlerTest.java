package uk.gov.di.ipv.core.resetsessionidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_DELETE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_RESET_TYPE;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.ALL;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.NAME_ONLY_CHANGE;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.PENDING_DCMAW_ALL;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.PENDING_F2F_ALL;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.REINSTATE;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;

@ExtendWith(MockitoExtension.class)
class ResetSessionIdentityHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_EMAIL_ADDRESS = "test.test@example.com";
    private static final String STATUS_CODE = "statusCode";
    public static final String TEST_EVCS_TOKEN = "test-evcs-token";
    private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Mock private ConfigService mockConfigService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private Context mockContext;
    @Mock private CriResponseService mockCriResponseService;
    @Mock private EvcsService mockEvcsService;
    @Mock private VerifiableCredential mockVerifiableCredential;
    @InjectMocks private ResetSessionIdentityHandler resetSessionIdentityHandler;

    @BeforeEach
    void setUpEach() {
        ipvSessionItem = spy(new IpvSessionItem());
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setEmailAddress(TEST_EMAIL_ADDRESS);
        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .clientId("test-client")
                        .govukSigninJourneyId(TEST_JOURNEY_ID)
                        .evcsAccessToken(TEST_EVCS_TOKEN)
                        .build();
    }

    @Test
    void handleRequestShouldDeleteUsersSessionVcsAndReturnNext() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", ALL.name()))
                        .build();

        // Act
        var journeyResponse =
                OBJECT_MAPPER.convertValue(
                        resetSessionIdentityHandler.handleRequest(event, mockContext),
                        JourneyResponse.class);

        // Assert
        verifyVotSetToP0();

        verify(mockSessionCredentialsService)
                .deleteSessionCredentialsForResetType(ipvSessionItem.getIpvSessionId(), ALL);

        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }

    @Test
    void handleRequestShouldCleanupVcsAndReturnNext_forPendingF2f() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", PENDING_F2F_ALL.name()))
                        .build();

        // Act
        var journeyResponse =
                OBJECT_MAPPER.convertValue(
                        resetSessionIdentityHandler.handleRequest(event, mockContext),
                        JourneyResponse.class);

        // Assert
        verifyVotSetToP0();

        verify(mockSessionCredentialsService)
                .deleteSessionCredentialsForResetType(
                        ipvSessionItem.getIpvSessionId(), PENDING_F2F_ALL);
        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, F2F);
        verify(mockEvcsService).abandonPendingIdentity(TEST_USER_ID, TEST_EVCS_TOKEN);

        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }

    @Test
    void shouldReturnErrorJourneyIfFailureToUpdatePendingIdentityInEvcs() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        doThrow(
                        new EvcsServiceException(
                                HTTPResponse.SC_SERVER_ERROR, FAILED_AT_EVCS_HTTP_REQUEST_SEND))
                .when(mockEvcsService)
                .abandonPendingIdentity(TEST_USER_ID, TEST_EVCS_TOKEN);

        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", PENDING_F2F_ALL.name()))
                        .build();

        // Act
        var journeyResponse = resetSessionIdentityHandler.handleRequest(event, mockContext);

        // Assert
        verifyVotSetToP0();

        verify(mockSessionCredentialsService)
                .deleteSessionCredentialsForResetType(
                        ipvSessionItem.getIpvSessionId(), PENDING_F2F_ALL);
        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, F2F);
        verify(mockEvcsService).abandonPendingIdentity(TEST_USER_ID, TEST_EVCS_TOKEN);

        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.get("journey"));
        assertEquals(500, journeyResponse.get(STATUS_CODE));
        assertEquals(FAILED_AT_EVCS_HTTP_REQUEST_SEND.getCode(), journeyResponse.get("code"));
        assertEquals(FAILED_AT_EVCS_HTTP_REQUEST_SEND.getMessage(), journeyResponse.get("message"));
    }

    @Test
    void handleRequestShouldCleanupVcsAndReturnNextForPendingDcmaw() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", PENDING_DCMAW_ALL.name()))
                        .build();

        // Act
        var journeyResponse =
                OBJECT_MAPPER.convertValue(
                        resetSessionIdentityHandler.handleRequest(event, mockContext),
                        JourneyResponse.class);

        // Assert
        verifyVotSetToP0();

        verify(mockSessionCredentialsService)
                .deleteSessionCredentialsForResetType(
                        ipvSessionItem.getIpvSessionId(), PENDING_DCMAW_ALL);
        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, DCMAW_ASYNC);
        verify(mockEvcsService).abandonPendingIdentity(TEST_USER_ID, TEST_EVCS_TOKEN);

        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }

    @Test
    void shouldReinstateUsersIdentity() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.getVerifiableCredentials(TEST_USER_ID, TEST_EVCS_TOKEN, CURRENT))
                .thenReturn(List.of(mockVerifiableCredential));

        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", REINSTATE.name()))
                        .build();

        // Act
        var journeyResponse =
                OBJECT_MAPPER.convertValue(
                        resetSessionIdentityHandler.handleRequest(event, mockContext),
                        JourneyResponse.class);

        // Assert
        verifyVotSetToP0();

        verify(mockSessionCredentialsService)
                .deleteSessionCredentialsForResetType(ipvSessionItem.getIpvSessionId(), REINSTATE);
        verify(mockSessionCredentialsService)
                .persistCredentials(List.of(mockVerifiableCredential), TEST_SESSION_ID, false);

        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }

    @Test
    void shouldReturnErrorJourneyIfReinstateAndUnableToReadFromLongTermStore() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.getVerifiableCredentials(TEST_USER_ID, TEST_EVCS_TOKEN, CURRENT))
                .thenThrow(new CredentialParseException("Boop"));

        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", REINSTATE.name()))
                        .build();

        // Act
        var journeyResponse =
                OBJECT_MAPPER.convertValue(
                        resetSessionIdentityHandler.handleRequest(event, mockContext),
                        JourneyErrorResponse.class);

        // Assert
        verifyVotSetToP0();

        verify(mockSessionCredentialsService)
                .deleteSessionCredentialsForResetType(ipvSessionItem.getIpvSessionId(), REINSTATE);

        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnErrorJourneyIfIpvSessionIdMissing() {
        // Arrange
        var event =
                ProcessRequest.processRequestBuilder()
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", ALL.name()))
                        .build();

        // Act
        var journeyResponse = resetSessionIdentityHandler.handleRequest(event, mockContext);

        // Assert
        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.get("journey"));
        assertEquals(400, journeyResponse.get(STATUS_CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getCode(), journeyResponse.get("code"));
        assertEquals(MISSING_IPV_SESSION_ID.getMessage(), journeyResponse.get("message"));
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantDeleteSessionCredentials() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        doThrow(new VerifiableCredentialException(418, FAILED_TO_DELETE_CREDENTIAL))
                .when(mockSessionCredentialsService)
                .deleteSessionCredentialsForResetType(TEST_SESSION_ID, NAME_ONLY_CHANGE);
        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", NAME_ONLY_CHANGE.name()))
                        .build();

        // Act
        var journeyResponse = resetSessionIdentityHandler.handleRequest(event, mockContext);

        // Assert
        verifyVotSetToP0();

        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.get("journey"));
        assertEquals(418, journeyResponse.get(STATUS_CODE));
        assertEquals(FAILED_TO_DELETE_CREDENTIAL.getCode(), journeyResponse.get("code"));
        assertEquals(FAILED_TO_DELETE_CREDENTIAL.getMessage(), journeyResponse.get("message"));
    }

    @Test
    void shouldReturnErrorJourneyIfUnknownResetType() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", "SAUSAGES"))
                        .build();

        // Act
        var journeyResponse = resetSessionIdentityHandler.handleRequest(event, mockContext);

        // Assert
        verifyVotSetToP0();

        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.get("journey"));
        assertEquals(500, journeyResponse.get(STATUS_CODE));
        assertEquals(UNKNOWN_RESET_TYPE.getCode(), journeyResponse.get("code"));
        assertEquals(UNKNOWN_RESET_TYPE.getMessage(), journeyResponse.get("message"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));
        var event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", "SAUSAGES"))
                        .build();

        var logCollector = LogCollector.getLogCollectorFor(ResetSessionIdentityHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> resetSessionIdentityHandler.handleRequest(event, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private void verifyVotSetToP0() {
        InOrder inOrder = inOrder(ipvSessionItem, mockIpvSessionService);
        inOrder.verify(ipvSessionItem).setVot(P0);
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verifyNoMoreInteractions();
    }
}
