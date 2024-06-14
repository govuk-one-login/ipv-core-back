package uk.gov.di.ipv.core.resetsessionidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.Map;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_DELETE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_RESET_TYPE;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.ALL;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.NAME_ONLY_CHANGE;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

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
    private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private Context mockContext;
    @InjectMocks private ResetSessionIdentityHandler resetSessionIdentityHandler;
    @Mock private ConfigService mockConfigService;

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
                        .build();
    }

    @Test
    void handleRequestShouldDeleteUsersSessionVcsAndReturnNext() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", "ALL"))
                        .build();

        // Act
        JourneyResponse journeyResponse =
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
    void shouldReturnErrorJourneyIfIpvSessionIdMissing() {
        // Arrange
        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", "ALL"))
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
        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of("resetType", "NAME_ONLY_CHANGE"))
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
    void shouldReturnErrorJourneyIfUnknownResetType() {
        // Arrange
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        ProcessRequest event =
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
        assertEquals(SC_INTERNAL_SERVER_ERROR, journeyResponse.get(STATUS_CODE));
        assertEquals(UNKNOWN_RESET_TYPE.getCode(), journeyResponse.get("code"));
        assertEquals(UNKNOWN_RESET_TYPE.getMessage(), journeyResponse.get("message"));
    }

    private void verifyVotSetToP0() {
        InOrder inOrder = inOrder(ipvSessionItem, mockIpvSessionService);
        inOrder.verify(ipvSessionItem).setVot(P0);
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verifyNoMoreInteractions();
    }
}
