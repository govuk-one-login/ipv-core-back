package uk.gov.di.ipv.core.resetipvsession;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_RESET_IPV_SESSION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.DELETE_ONLY_GPG45_VCS;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IS_USER_INITIATED;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

@ExtendWith(MockitoExtension.class)
class ResetIpvSessionHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_EMAIL_ADDRESS = "test.test@example.com";
    private static final String TEST_JOURNEY = "journey/reset-ipv-session";
    private static final String STATUS_CODE = "statusCode";
    private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private Context mockContext;
    @InjectMocks private ResetIpvSessionHandler resetIpvSessionHandler;
    @Mock private ConfigService mockConfigService;

    @BeforeEach
    void setUpEach() {
        ipvSessionItem = new IpvSessionItem();
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
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of(IS_USER_INITIATED, false, DELETE_ONLY_GPG45_VCS, false))
                        .build();

        // Act
        JourneyResponse journeyResponse =
                OBJECT_MAPPER.convertValue(
                        resetIpvSessionHandler.handleRequest(event, mockContext),
                        JourneyResponse.class);

        // Assert
        verify(mockSessionCredentialsService)
                .deleteSessionCredentials(ipvSessionItem.getIpvSessionId());
        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }

    @Test
    void shouldReturnErrorJourneyIfIpvSessionIdMissing() throws Exception {
        // Arrange
        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of(IS_USER_INITIATED, false, DELETE_ONLY_GPG45_VCS, false))
                        .build();

        // Act
        var journeyResponse = resetIpvSessionHandler.handleRequest(event, mockContext);

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
        doThrow(new VerifiableCredentialException(418, FAILED_TO_RESET_IPV_SESSION))
                .when(mockSessionCredentialsService)
                .deleteSessionCredentials(ipvSessionItem.getIpvSessionId());
        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of(IS_USER_INITIATED, false, DELETE_ONLY_GPG45_VCS, false))
                        .build();

        // Act
        var journeyResponse = resetIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.get("journey"));
        assertEquals(418, journeyResponse.get(STATUS_CODE));
        assertEquals(FAILED_TO_RESET_IPV_SESSION.getCode(), journeyResponse.get("code"));
        assertEquals(FAILED_TO_RESET_IPV_SESSION.getMessage(), journeyResponse.get("message"));
    }
}
