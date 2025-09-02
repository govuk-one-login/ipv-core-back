package uk.gov.di.ipv.core.userreverification;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionReverification;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.domain.ReverificationFailureCode;
import uk.gov.di.ipv.core.library.domain.ReverificationResponse;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.ConfigServiceHelper;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;

@ExtendWith(MockitoExtension.class)
class UserReverificationHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_IPV_SESSION_ID = SecureTokenHelper.getInstance().generate();
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_ACCESS_TOKEN = "test-access-token";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String REVERIFICATION_SCOPE = "reverification email phone";
    private static final String REVERIFICATION_REQUEST = "/reverification";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();

    private static final APIGatewayProxyRequestEvent testEvent = getEventWithAuthAndIpHeaders();

    @Mock private Context mockContext;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private AuditService mockAuditService;
    @InjectMocks private UserReverificationHandler userReverificationHandler;

    private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeEach
    void setUp() {
        ConfigServiceHelper.stubDefaultComponentIdConfig(mockConfigService, mockConfig);
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setAccessToken(TEST_ACCESS_TOKEN);
        ipvSessionItem.setAccessTokenMetadata(new AccessTokenMetadata());
        ipvSessionItem.setReverificationStatus(ReverificationStatus.SUCCESS);
        clientOAuthSessionItem = getClientAuthSessionItemWithScope(REVERIFICATION_SCOPE);
    }

    @Test
    void shouldReturnSuccsessfulReverificationResponseOnFailedReverification() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        // Act
        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        ReverificationResponse reverificationResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertTrue(reverificationResponse.success());
        assertEquals(TEST_USER_ID, reverificationResponse.sub());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);
        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_REVERIFY_END, auditEvent.getEventName());
        assertEquals(new AuditExtensionReverification(true, null), auditEvent.getExtensions());
    }

    @Test
    void
            shouldReturnUnsuccsessfulReverificationResponseWithDefaultFailureCodeOnSuccessfulReverification()
                    throws Exception {
        // Arrange
        ipvSessionItem.setReverificationStatus(ReverificationStatus.FAILED);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        // Act
        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        ReverificationResponse reverificationResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertFalse(reverificationResponse.success());
        assertEquals(TEST_USER_ID, reverificationResponse.sub());
        assertEquals(
                ReverificationFailureCode.IDENTITY_CHECK_INCOMPLETE.getFailureCode(),
                reverificationResponse.failureCode());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);
        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_REVERIFY_END, auditEvent.getEventName());
        assertEquals(
                new AuditExtensionReverification(false, "identity_check_incomplete"),
                auditEvent.getExtensions());
    }

    static Stream<Arguments> returnCodesTestCases() {
        return Stream.of(
                Arguments.of(ReverificationFailureCode.IDENTITY_CHECK_INCOMPLETE),
                Arguments.of(ReverificationFailureCode.IDENTITY_DID_NOT_MATCH),
                Arguments.of(ReverificationFailureCode.NO_IDENTITY_AVAILABLE));
    }

    @ParameterizedTest
    @MethodSource("returnCodesTestCases")
    void shouldReturnCorrectFailureCodeFromIpvSession(ReverificationFailureCode failureCode)
            throws Exception {
        // Arrange
        ipvSessionItem.setReverificationStatus(ReverificationStatus.FAILED);
        ipvSessionItem.setFailureCode(failureCode);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        // Act
        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        ReverificationResponse reverificationResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertFalse(reverificationResponse.success());
        assertEquals(failureCode.getFailureCode(), reverificationResponse.failureCode());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_REVERIFY_END, auditEvent.getEventName());
        assertEquals(
                new AuditExtensionReverification(false, failureCode.getFailureCode()),
                auditEvent.getExtensions());
    }

    @Test
    void shouldReturnErrorResponseWhenAccessTokenHasExpired() throws Exception {
        AccessTokenMetadata expiredAccessTokenMetadata = new AccessTokenMetadata();
        expiredAccessTokenMetadata.setExpiryDateTime(Instant.now().minusSeconds(5).toString());
        ipvSessionItem.setAccessTokenMetadata(expiredAccessTokenMetadata);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(testEvent, mockContext);
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void shouldReturnErrorResponseWhenIpvSessionNotFoundExceptionThrown() throws Exception {
        AccessTokenMetadata expiredAccessTokenMetadata = new AccessTokenMetadata();
        expiredAccessTokenMetadata.setExpiryDateTime(Instant.now().minusSeconds(5).toString());
        ipvSessionItem.setAccessTokenMetadata(expiredAccessTokenMetadata);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenThrow(new IpvSessionNotFoundException("err", new Exception()));

        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(testEvent, mockContext);
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void shouldReturnErrorResponseWhenAccessTokenHasBeenRevoked() throws Exception {
        AccessTokenMetadata revokedAccessTokenMetadata = new AccessTokenMetadata();
        revokedAccessTokenMetadata.setRevokedAtDateTime(Instant.now().toString());
        ipvSessionItem.setAccessTokenMetadata(revokedAccessTokenMetadata);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(testEvent, mockContext);
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has been revoked")
                        .getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsInvalid() throws Exception {

        // Arrange
        APIGatewayProxyRequestEvent event = testEvent.clone();
        event.setHeaders(
                Map.of("Authorization", "invalid-bearer-token", "ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, String> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.INVALID_REQUEST.getDescription(),
                responseBody.get("error_description"));

        verify(mockUserIdentityService, never())
                .generateUserIdentity(any(), any(), any(), any(), any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void shouldReturnErrorResponseWhenScopeIsInvalid() throws Exception {

        // Arrange
        ClientOAuthSessionItem clientOAuthSessionItemWithScope =
                getClientAuthSessionItemWithScope("a-different-scope");

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItemWithScope);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(true);

        // Act
        APIGatewayProxyResponseEvent response =
                userReverificationHandler.handleRequest(testEvent, mockContext);

        // Assert
        Map<String, String> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - Access was attempted from an invalid endpoint or journey.")
                        .getDescription(),
                responseBody.get("error_description"));

        verify(mockUserIdentityService, never())
                .generateUserIdentity(any(), any(), any(), any(), any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSessionByAccessToken(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(UserReverificationHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> userReverificationHandler.handleRequest(testEvent, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private static APIGatewayProxyRequestEvent getEventWithAuthAndIpHeaders() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);
        event.setPath(REVERIFICATION_REQUEST);
        return event;
    }

    private static ClientOAuthSessionItem getClientAuthSessionItemWithScope(String scope) {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                .state("test-state")
                .responseType("code")
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("test-journey-id")
                .userId(TEST_USER_ID)
                .clientId("test-client")
                .govukSigninJourneyId("test-journey-id")
                .scope(scope)
                .build();
    }
}
