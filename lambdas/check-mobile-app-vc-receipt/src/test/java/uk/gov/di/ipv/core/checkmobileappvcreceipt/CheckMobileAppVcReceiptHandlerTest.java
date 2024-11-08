package uk.gov.di.ipv.core.checkmobileappvcreceipt;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CheckMobileAppVcReceiptHandlerTest {
    private static final String TEST_IPV_SESSION_ID = "test_ipv_session_id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = "test_client_oauth_id";
    private static final String TEST_USER_ID = "test_user_id";
    @Mock private Context mockContext;
    @Mock private SignedJWT mockSignedJwt;
    @Mock private ConfigService configService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CriResponseService criResponseService;
    @Mock private VerifiableCredentialService verifiableCredentialService;
    @InjectMocks private CheckMobileAppVcReceiptHandler checkMobileAppVcReceiptHandler;

    @Test
    void shouldReturnErrorWhenCallbackRequestMissingIpvSessionId() {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        requestEvent.setHeaders(Map.of());

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void shouldReturnErrorWhenIpvSessionNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenThrow(new IpvSessionNotFoundException(""));

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void shouldReturn500WhenCriResponseNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC)).thenReturn(null);

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    void shouldReturn200WhenStatusNotPending() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(buildValidCriResponseItem(CriResponseService.STATUS_RECEIVED));

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturn200WhenCriResponseStatusPendingButVcExists() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        var criResponseItem = buildValidCriResponseItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(criResponseItem);
        when(mockSignedJwt.getJWTClaimsSet())
                .thenReturn(
                        JWTClaimsSet.parse(
                                Map.of(
                                        "vc",
                                        Map.of("type", List.of("IdentityAssertionCredential")))));
        var vc = VerifiableCredential.fromValidJwt(TEST_USER_ID, Cri.DCMAW_ASYNC, mockSignedJwt);
        when(verifiableCredentialService.getVc(TEST_USER_ID, "dcmawAsync")).thenReturn(vc);

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturn404WhenCriResponseStatusPendingAndVcNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        var criResponseItem = buildValidCriResponseItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(criResponseItem);

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));
        var requestEvent = buildValidRequestEventWithState();

        var logCollector = LogCollector.GetLogCollectorFor(CheckMobileAppVcReceiptHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () ->
                                checkMobileAppVcReceiptHandler.handleRequest(
                                        requestEvent, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0).getFormattedMessage();
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private APIGatewayProxyRequestEvent buildValidRequestEventWithState() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("ipv-session-id", TEST_IPV_SESSION_ID));
        return event;
    }

    private IpvSessionItem buildValidIpvSessionItem() {
        var ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        return ipvSessionItem;
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }

    private CriResponseItem buildValidCriResponseItem(String status) {
        return CriResponseItem.builder()
                .userId(TEST_USER_ID)
                .credentialIssuer(Cri.DCMAW_ASYNC.getId())
                .status(status)
                .build();
    }
}
