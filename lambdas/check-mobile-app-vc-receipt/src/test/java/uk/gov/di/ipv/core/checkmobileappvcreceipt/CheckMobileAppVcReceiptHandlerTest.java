package uk.gov.di.ipv.core.checkmobileappvcreceipt;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.cricheckingservice.CriCheckingService;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ABANDON_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
class CheckMobileAppVcReceiptHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_IPV_SESSION_ID = "test_ipv_session_id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = "test_client_oauth_id";
    private static final String TEST_USER_ID = "test_user_id";
    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    @Mock private Context mockContext;
    @Mock private SignedJWT mockSignedJwt;
    @Mock private ConfigService configService;
    @Mock private Config mockConfig;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CriResponseService criResponseService;
    @Mock private CriCheckingService criCheckingService;
    @Mock private EvcsService evcsService;
    @Mock private SessionCredentialsService sessionCredentialsService;
    @InjectMocks private CheckMobileAppVcReceiptHandler checkMobileAppVcReceiptHandler;

    @BeforeEach
    void setUpEach() {
        when(configService.getComponentId()).thenReturn("https://core-component.example");
    }

    @Test
    void shouldReturnErrorWhenCallbackRequestMissingIpvSessionId() throws JsonProcessingException {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        requestEvent.setHeaders(Map.of());

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(response.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.BAD_REQUEST,
                        ErrorResponse.MISSING_IPV_SESSION_ID),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenIpvSessionNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenThrow(new IpvSessionNotFoundException(""));

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(response.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.BAD_REQUEST,
                        ErrorResponse.IPV_SESSION_NOT_FOUND),
                journeyResponse);
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
        var journeyResponse =
                OBJECT_MAPPER.readValue(response.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.CRI_RESPONSE_ITEM_NOT_FOUND),
                journeyResponse);
    }

    @Test
    void shouldReturn200WhenCriResponseStatusPendingButVcExists() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
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
        when(sessionCredentialsService.getCredentials(
                        ipvSessionItem.getIpvSessionId(), TEST_USER_ID))
                .thenReturn(List.of());
        when(evcsService.getVerifiableCredentials(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, PENDING_RETURN))
                .thenReturn(List.of(vc));
        when(criCheckingService.checkVcResponse(
                        List.of(vc), null, clientOAuthSessionItem, ipvSessionItem, List.of()))
                .thenReturn(new JourneyResponse(JOURNEY_NEXT_PATH));

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse = OBJECT_MAPPER.readValue(response.getBody(), JourneyResponse.class);

        // Assert
        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), journeyResponse);
        verify(sessionCredentialsService)
                .persistCredentials(List.of(vc), TEST_IPV_SESSION_ID, true);
    }

    @Test
    void shouldReturnAbandonJourneyResponseWhenCriResponseStatusAbandon() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        var criResponseItem = buildValidCriResponseItem(CriResponseService.STATUS_ABANDON);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(criResponseItem);

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse = OBJECT_MAPPER.readValue(response.getBody(), JourneyResponse.class);

        // Assert
        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(new JourneyResponse(JOURNEY_ABANDON_PATH), journeyResponse);
    }

    @Test
    void shouldReturnErrorJourneyResponseWhenCriResponseStatusError() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        var criResponseItem = buildValidCriResponseItem(CriResponseService.STATUS_ERROR);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(criResponseItem);

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse = OBJECT_MAPPER.readValue(response.getBody(), JourneyResponse.class);

        // Assert
        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(new JourneyResponse(JOURNEY_ERROR_PATH), journeyResponse);
    }

    @Test
    void shouldReturn404WhenVcNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        var criResponseItem = buildValidCriResponseItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(criResponseItem);
        when(evcsService.getVerifiableCredentials(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, PENDING_RETURN))
                .thenReturn(List.of());

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        assertEquals(HttpStatusCode.NOT_FOUND, response.getStatusCode());
        assertEquals("\"No VC found\"", response.getBody());
        verify(sessionCredentialsService, never()).persistCredentials(any(), any(), anyBoolean());
    }

    @Test
    void shouldReturn500IfUnableToExtractContraIndicatorsFromVc() throws Exception {
        // Arrange
        var ipvSessionItem = buildValidIpvSessionItem();
        var requestEvent = buildValidRequestEventWithState();
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSessionItem);
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
        when(sessionCredentialsService.getCredentials(
                        ipvSessionItem.getIpvSessionId(), TEST_USER_ID))
                .thenReturn(List.of());
        when(evcsService.getVerifiableCredentials(
                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, PENDING_RETURN))
                .thenReturn(List.of(vc));
        when(criCheckingService.checkVcResponse(any(), any(), any(), any(), any()))
                .thenThrow(new CiExtractionException("Unable to extract CIs"));

        // Act
        var response = checkMobileAppVcReceiptHandler.handleRequest(requestEvent, mockContext);

        // Assert
        Map<String, String> body =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Unable to extract CIs", body.get("message"));
        verify(sessionCredentialsService, times(1)).persistCredentials(any(), any(), anyBoolean());
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));
        var requestEvent = buildValidRequestEventWithState();

        var logCollector = LogCollector.getLogCollectorFor(CheckMobileAppVcReceiptHandler.class);

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
        var logMessage = logCollector.getLogMessages().get(0);
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
        return ClientOAuthSessionItem.builder()
                .userId(TEST_USER_ID)
                .evcsAccessToken(TEST_EVCS_ACCESS_TOKEN)
                .build();
    }

    private CriResponseItem buildValidCriResponseItem(String status) {
        return CriResponseItem.builder()
                .userId(TEST_USER_ID)
                .credentialIssuer(Cri.DCMAW_ASYNC.getId())
                .status(status)
                .build();
    }
}
