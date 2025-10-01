package uk.gov.di.ipv.core.processcricallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.cricheckingservice.CriCheckingService;
import uk.gov.di.ipv.core.library.cricheckingservice.exception.InvalidCriCallbackRequestException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_STORED_CIS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.INVALID_TOKEN_REQUEST;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
class ProcessCriCallbackHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_ERROR = "test_error";
    private static final String TEST_IPV_SESSION_ID = "test_ipv_session_id";
    private static final String TEST_CRI_OAUTH_SESSION_ID = "test_cri_oauth_session_id";
    private static final String TEST_USER_ID = "test_user_id";
    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;
    @Mock private VerifiableCredentialValidator mockVerifiableCredentialValidator;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private CriApiService mockCriApiService;
    @Mock private CriStoringService mockCriStoringService;
    @Mock private CriCheckingService mockCriCheckingService;
    @Mock private AuditService mockAuditService;
    @Mock private SessionCredentialsService sessionCredentialsService;
    @InjectMocks private ProcessCriCallbackHandler processCriCallbackHandler;

    @BeforeEach
    void setUp() {
        when(mockConfigService.getComponentId()).thenReturn("https://core-component.example");
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturnNextWhenAllChecksPassForCreatedVcs() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .verifiableCredentials(List.of(vcWebPassportSuccessful().getVcString()))
                        .credentialStatus(VerifiableCredentialStatus.CREATED)
                        .build();
        var vcs = List.of(vcWebPassportSuccessful());
        var sessionVcs = List.of(vcAddressM1a());

        when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        when(mockCriApiService.fetchVerifiableCredential(bearerToken, ADDRESS, criOAuthSessionItem))
                .thenReturn(vcResponse);
        when(mockVerifiableCredentialValidator.parseAndValidate(any(), any(), any(), any(), any()))
                .thenReturn(vcs);
        when(sessionCredentialsService.getCredentials(
                        ipvSessionItem.getIpvSessionId(), clientOAuthSessionItem.getUserId(), true))
                .thenReturn(sessionVcs);
        when(mockCriCheckingService.checkVcResponse(
                        any(),
                        eq(callbackRequest.getIpAddress()),
                        eq(clientOAuthSessionItem),
                        eq(ipvSessionItem),
                        eq(sessionVcs)))
                .thenReturn(new JourneyResponse(JOURNEY_NEXT_PATH));
        when(mockConfigService.getOauthCriConfig(any()))
                .thenReturn(
                        OauthCriConfig.builder()
                                .tokenUrl(new URI(""))
                                .credentialUrl(new URI(""))
                                .authorizeUrl(new URI(""))
                                .clientId("ipv-core")
                                .signingKey(TestFixtures.TEST_EC_PUBLIC_JWK)
                                .componentId("")
                                .clientCallbackUrl(new URI(""))
                                .requiresApiKey(false)
                                .requiresAdditionalEvidence(false)
                                .build());

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyResponse.class);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), journeyResponse);
        verify(mockCriCheckingService).validateSessionIds(callbackRequest);
        verify(mockCriCheckingService)
                .validateCallbackRequest(callbackRequest, criOAuthSessionItem);
        verify(mockCriStoringService)
                .storeVcs(
                        callbackRequest.getCredentialIssuer(),
                        callbackRequest.getIpAddress(),
                        callbackRequest.getDeviceInformation(),
                        vcs,
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        sessionVcs);
    }

    @Test
    void shouldReturnNextWhenAllChecksPassForPendingVcs() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .credentialStatus(VerifiableCredentialStatus.PENDING)
                        .build();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        when(mockCriApiService.fetchVerifiableCredential(bearerToken, ADDRESS, criOAuthSessionItem))
                .thenReturn(vcResponse);
        when(mockCriCheckingService.checkVcResponse(
                        List.of(),
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        List.of()))
                .thenReturn(new JourneyResponse(JOURNEY_NEXT_PATH));

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyResponse.class);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), journeyResponse);
        verify(mockCriCheckingService).validateSessionIds(callbackRequest);
        verify(mockCriStoringService).recordCriResponse(callbackRequest, clientOAuthSessionItem);
    }

    @Test
    void shouldReturnAttemptRecoveryPageResponseWhenValidateSessionIdsFails() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        doThrow(new InvalidCriCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE))
                .when(mockCriCheckingService)
                .validateSessionIds(callbackRequest);

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var errorPageResponse =
                OBJECT_MAPPER.readValue(
                        lambdaResponse.getBody(), new TypeReference<Map<String, Object>>() {});
        assertEquals("error", errorPageResponse.get("type"));
        assertEquals(400, errorPageResponse.get("statusCode"));
        assertEquals("pyi-attempt-recovery", errorPageResponse.get("page"));
    }

    @Test
    void shouldReturnJourneyErrorResponseWhenCriCheckingServiceThrows() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .verifiableCredentials(List.of(vcWebPassportSuccessful().getVcString()))
                        .credentialStatus(VerifiableCredentialStatus.CREATED)
                        .build();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        when(mockCriApiService.fetchVerifiableCredential(bearerToken, ADDRESS, criOAuthSessionItem))
                .thenReturn(vcResponse);
        when(mockConfigService.getOauthCriConfig(any()))
                .thenReturn(
                        OauthCriConfig.builder()
                                .tokenUrl(new URI(""))
                                .credentialUrl(new URI(""))
                                .authorizeUrl(new URI(""))
                                .clientId("ipv-core")
                                .signingKey(TestFixtures.TEST_EC_PUBLIC_JWK)
                                .componentId("")
                                .clientCallbackUrl(new URI(""))
                                .requiresApiKey(false)
                                .requiresAdditionalEvidence(false)
                                .build());
        when(mockCriCheckingService.checkVcResponse(
                        any(),
                        eq(callbackRequest.getIpAddress()),
                        eq(clientOAuthSessionItem),
                        eq(ipvSessionItem),
                        any()))
                .thenThrow(new CiRetrievalException("failed to get CI"));

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var journeyErrorResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);
        assertEquals(FAILED_TO_GET_STORED_CIS.getCode(), journeyErrorResponse.getCode());
        assertEquals(500, journeyErrorResponse.getStatusCode());
    }

    @Test
    void shouldReturnJourneyErrorResponseWhenAccessTokenCannotBeFetched() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        doThrow(new CriApiException(HTTPResponse.SC_BAD_REQUEST, INVALID_TOKEN_REQUEST))
                .when(mockCriApiService)
                .fetchAccessToken(eq(callbackRequest), any(CriOAuthSessionItem.class));

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var journeyErrorResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);
        assertEquals(INVALID_TOKEN_REQUEST.getCode(), journeyErrorResponse.getCode());
        assertEquals(400, journeyErrorResponse.getStatusCode());
    }

    @Test
    void shouldReturnJourneyErrorResponseWhenVerifiableCredentialCannotBeFetched()
            throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        doThrow(
                        new CriApiException(
                                HTTPResponse.SC_BAD_REQUEST, FAILED_TO_EXCHANGE_AUTHORIZATION_CODE))
                .when(mockCriApiService)
                .fetchVerifiableCredential(
                        any(BearerAccessToken.class), eq(ADDRESS), any(CriOAuthSessionItem.class));

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var journeyErrorResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);
        assertEquals(
                FAILED_TO_EXCHANGE_AUTHORIZATION_CODE.getCode(), journeyErrorResponse.getCode());
        assertEquals(400, journeyErrorResponse.getStatusCode());
    }

    @Test
    void shouldReturnJourneyResponseWhenErrorResponseFromCri() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setError(TEST_ERROR);
        var requestEvent = buildValidRequestEvent(callbackRequest);

        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriCheckingService.handleCallbackError(
                        eq(callbackRequest), any(ClientOAuthSessionItem.class)))
                .thenReturn(new JourneyResponse(JOURNEY_ERROR_PATH));

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyResponse.class);
        assertEquals(new JourneyResponse(JOURNEY_ERROR_PATH), journeyResponse);
        verify(mockCriCheckingService).validateOAuthForError(eq(callbackRequest), any(), any());
    }

    @Test
    void shouldReturnTimeoutRecoverablePageForCriOAuthSessionException() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        doThrow(new InvalidCriCallbackRequestException(ErrorResponse.NO_IPV_FOR_CRI_OAUTH_SESSION))
                .when(mockCriCheckingService)
                .validateSessionIds(callbackRequest);

        // Act
        var lambdaResponse = processCriCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var errorPageResponse =
                OBJECT_MAPPER.readValue(
                        lambdaResponse.getBody(), new TypeReference<Map<String, Object>>() {});
        assertEquals("error", errorPageResponse.get("type"));
        assertEquals(401, errorPageResponse.get("statusCode"));
        assertEquals("pyi-timeout-recoverable", errorPageResponse.get("page"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));
        var callbackRequest = buildValidCallbackRequest();
        var requestEvent = buildValidRequestEvent(callbackRequest);

        var logCollector = LogCollector.getLogCollectorFor(ProcessCriCallbackHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> processCriCallbackHandler.handleRequest(requestEvent, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private CriCallbackRequest buildValidCallbackRequest() {
        return CriCallbackRequest.builder()
                .credentialIssuerId(ADDRESS.getId())
                .authorizationCode(TEST_AUTHORISATION_CODE)
                .state(TEST_CRI_OAUTH_SESSION_ID)
                .build();
    }

    private APIGatewayProxyRequestEvent buildValidRequestEvent(CriCallbackRequest callbackRequest)
            throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(OBJECT_MAPPER.writeValueAsString(callbackRequest));

        event.setHeaders(Map.of("ipv-session-id", TEST_IPV_SESSION_ID));

        // These get set on the callback request in the handler after parsing it from the event
        // body.
        // Setting them here to keep the test cases tidier.
        callbackRequest.setIpvSessionId(TEST_IPV_SESSION_ID);
        callbackRequest.setFeatureSet(List.of());

        return event;
    }

    private CriOAuthSessionItem buildValidCriOAuthSessionItem() {
        return CriOAuthSessionItem.builder()
                .criId(ADDRESS.getId())
                .criOAuthSessionId(TEST_CRI_OAUTH_SESSION_ID)
                .build();
    }

    private IpvSessionItem buildValidIpvSessionItem() {
        var ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.setCriOAuthSessionId(TEST_CRI_OAUTH_SESSION_ID);
        return ipvSessionItem;
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }
}
