package uk.gov.di.ipv.core.resetidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EmailService;
import uk.gov.di.ipv.core.library.service.EmailServiceFactory;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;

@ExtendWith(MockitoExtension.class)
public class ResetIdentityHandlerTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_EMAIL_ADDRESS = "test.test@example.com";
    private static final String TEST_JOURNEY = "journey/reset-identity";
    private static final String IS_USER_INITIATED = "isUserInitiated";

    @Mock private Context context;
    @Mock private VerifiableCredentialService verifiableCredentialService;
    @Mock private CriResponseService criResponseService;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private ConfigService configService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private EmailServiceFactory emailServiceFactory;
    @Mock private EmailService emailService;
    @InjectMocks private ResetIdentityHandler resetIdentityHandler;

    private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

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
    void handleRequest_whenNotUserInitiated_shouldDeleteUsersVcsAndReturnNext()
            throws SqsException {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of(IS_USER_INITIATED, false))
                        .build();

        // Act
        JourneyResponse journeyResponse =
                objectMapper.convertValue(
                        resetIdentityHandler.handleRequest(event, context), JourneyResponse.class);

        // Assert
        verify(verifiableCredentialService).deleteVcStoreItems(TEST_USER_ID, false);
        verify(criResponseService).deleteCriResponseItem(TEST_USER_ID, F2F_CRI);
        verifyNoInteractions(mockAuditService);
        verifyNoInteractions(emailService);
        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }

    @Test
    void handleRequest_whenUserInitiated_shouldSendEmailAndRaiseAuditLog() throws SqsException {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of(IS_USER_INITIATED, true))
                        .build();
        when(emailServiceFactory.getEmailService()).thenReturn(emailService);

        // Act
        JourneyResponse journeyResponse =
                objectMapper.convertValue(
                        resetIdentityHandler.handleRequest(event, context), JourneyResponse.class);

        // Assert
        verify(verifiableCredentialService).deleteVcStoreItems(TEST_USER_ID, true);
        verify(criResponseService).deleteCriResponseItem(TEST_USER_ID, F2F_CRI);
        verify(mockAuditService, times(1)).sendAuditEvent((AuditEvent) any());
        verify(emailService, times(1))
                .sendUserTriggeredIdentityResetConfirmation(eq(TEST_EMAIL_ADDRESS), any());
        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }

    @Test
    void handleRequest_whenUserInitiatedF2F_shouldSendEmailAndRaiseAuditLog() throws SqsException {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID))
                .thenReturn(new CriResponseItem());

        ProcessRequest event =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .lambdaInput(Map.of(IS_USER_INITIATED, true))
                        .build();
        when(emailServiceFactory.getEmailService()).thenReturn(emailService);

        // Act
        JourneyResponse journeyResponse =
                objectMapper.convertValue(
                        resetIdentityHandler.handleRequest(event, context), JourneyResponse.class);

        // Assert
        verify(verifiableCredentialService).deleteVcStoreItems(TEST_USER_ID, true);
        verify(criResponseService).deleteCriResponseItem(TEST_USER_ID, F2F_CRI);
        verify(mockAuditService, times(1)).sendAuditEvent((AuditEvent) any());
        verify(emailService, times(1))
                .sendUserTriggeredF2FIdentityResetConfirmation(eq(TEST_EMAIL_ADDRESS), any());
        assertEquals(JOURNEY_NEXT.getJourney(), journeyResponse.getJourney());
    }
}
