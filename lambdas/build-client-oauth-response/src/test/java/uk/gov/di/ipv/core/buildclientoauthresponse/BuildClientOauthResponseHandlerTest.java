package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URIBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionAccountIntervention;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;

@ExtendWith(MockitoExtension.class)
class BuildClientOauthResponseHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final String TEST_FEATURE_SET = "fs-001";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private Context context;
    @Mock private IpvSessionService mockSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;
    @Mock private AuthRequestValidator mockAuthRequestValidator;
    @Mock private AuditService mockAuditService;
    @InjectMocks private BuildClientOauthResponseHandler handler;
    private String authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode().getValue();

        when(mockConfigService.getComponentId()).thenReturn("https://core-component.example");
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequest() throws Exception {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItem = spy(generateIpvSessionItem());
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .featureSet("someCoolNewThing")
                        .build();

        ClientResponse clientResponse =
                toResponseClass(handler.handleRequest(event, context), ClientResponse.class);

        verify(mockSessionService)
                .setAuthorizationCode(eq(ipvSessionItem), anyString(), eq("https://example.com"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_END, auditEventCaptor.getValue().getEventName());

        URI expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode)
                        .addParameter("state", "test-state")
                        .build();

        URI actualRedirectUrl = new URI(clientResponse.getClient().getRedirectUrl());
        List<NameValuePair> params = new URIBuilder(actualRedirectUrl).getQueryParams();
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertNotNull(params.get(0).getValue());
        assertEquals("test-state", params.get(1).getValue());

        InOrder inOrder = inOrder(ipvSessionItem, mockSessionService);
        inOrder.verify(ipvSessionItem).setFeatureSetFromList(List.of("someCoolNewThing"));
        inOrder.verify(mockSessionService).updateIpvSession(ipvSessionItem);
    }

    @ParameterizedTest
    @MethodSource("testParamsForSuccessfulOauthRequestForReproveIdentity")
    void shouldReturn200OnSuccessfulOauthRequestForReproveIdentity(
            Vot vot, String vtr, boolean success) throws Exception {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItem = spy(generateIpvSessionItem());
        ipvSessionItem.setVot(vot);
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        var oauthSessionItem = getClientOAuthSessionItem();
        oauthSessionItem.setReproveIdentity(true);
        oauthSessionItem.setVtr(List.of(vtr));
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(oauthSessionItem);

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .featureSet("someCoolNewThing")
                        .build();

        ClientResponse clientResponse =
                toResponseClass(handler.handleRequest(event, context), ClientResponse.class);

        verify(mockSessionService)
                .setAuthorizationCode(eq(ipvSessionItem), anyString(), eq("https://example.com"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var capturedValues = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_JOURNEY_END, capturedValues.get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_ACCOUNT_INTERVENTION_END, capturedValues.get(1).getEventName());
        AuditExtensionAccountIntervention extensions =
                (AuditExtensionAccountIntervention) capturedValues.get(1).getExtensions();
        assertEquals("reprove_identity", extensions.getType());
        assertEquals(success, extensions.getSuccess());

        URI expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode)
                        .addParameter("state", "test-state")
                        .build();

        URI actualRedirectUrl = new URI(clientResponse.getClient().getRedirectUrl());
        List<NameValuePair> params = new URIBuilder(actualRedirectUrl).getQueryParams();
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertNotNull(params.get(0).getValue());
        assertEquals("test-state", params.get(1).getValue());

        InOrder inOrder = inOrder(ipvSessionItem, mockSessionService);
        inOrder.verify(ipvSessionItem).setFeatureSetFromList(List.of("someCoolNewThing"));
        inOrder.verify(mockSessionService).updateIpvSession(ipvSessionItem);
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequest_withNullIpvSessionAndClientSessionIdInRequest()
            throws Exception {
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .build();

        ClientResponse clientResponse =
                toResponseClass(handler.handleRequest(event, context), ClientResponse.class);

        URI actualRedirectUrl = new URI(clientResponse.getClient().getRedirectUrl());
        List<NameValuePair> params = new URIBuilder(actualRedirectUrl).getQueryParams();
        assertEquals("example.com", actualRedirectUrl.getHost());
        assertEquals("access_denied", params.get(0).getValue());
        assertEquals("Missing Context", params.get(1).getValue());
        assertEquals("test-state", params.get(2).getValue());
        verify(mockConfigService).setFeatureSet(List.of(TEST_FEATURE_SET));
    }

    @Test
    void shouldReturn400_withBothIpvSessionAndClientSessionIdNullInRequest() {
        JourneyRequest event = JourneyRequest.builder().ipAddress(TEST_IP_ADDRESS).build();

        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(event, context), JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.BAD_REQUEST, errorResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_SESSION_ID.getCode(), errorResponse.getCode());
        assertEquals(ErrorResponse.MISSING_SESSION_ID.getMessage(), errorResponse.getMessage());
    }

    @Test
    void shouldReturn200WhenStateNotInSession() throws Exception {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setState("");
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();

        ClientResponse clientResponse =
                toResponseClass(handler.handleRequest(event, context), ClientResponse.class);

        URI expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode)
                        .build();
        URI actualRedirectUrl = new URI(clientResponse.getClient().getRedirectUrl());
        List<NameValuePair> params = new URIBuilder(actualRedirectUrl).getQueryParams();
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertEquals(1, params.size());
        assertNotNull(params.get(0).getValue());
    }

    @Test
    void shouldReturn400IfRequestFailsValidation() throws Exception {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS));
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();

        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(event, context), JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.BAD_REQUEST, errorResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), errorResponse.getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), errorResponse.getMessage());

        verify(mockSessionService, never()).setAuthorizationCode(any(), anyString(), anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = {OAuth2RequestParams.CLIENT_ID, OAuth2RequestParams.RESPONSE_TYPE})
    void shouldReturn400IfCanNotParseAuthRequestFromQueryStringParams(String param)
            throws Exception {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());

        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        if (param.equals(OAuth2RequestParams.CLIENT_ID)) {
            clientOAuthSessionItem.setClientId(null);
        } else if (param.equals(OAuth2RequestParams.RESPONSE_TYPE)) {
            clientOAuthSessionItem.setResponseType(null);
        }
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();

        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(event, context), JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.BAD_REQUEST, errorResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                errorResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                errorResponse.getMessage());
        verify(mockSessionService, never()).setAuthorizationCode(any(), anyString(), anyString());
    }

    @Test
    void shouldReturn200WithErrorParams() throws Exception {
        IpvSessionItem ipvSessionItemWithError = generateIpvSessionItem();
        ipvSessionItemWithError.setErrorCode(OAuth2Error.SERVER_ERROR_CODE);
        ipvSessionItemWithError.setErrorDescription("Test error description");
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItemWithError);
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();

        ClientResponse clientResponse =
                toResponseClass(handler.handleRequest(event, context), ClientResponse.class);

        URIBuilder uriBuilder = new URIBuilder(clientResponse.getClient().getRedirectUrl());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, uriBuilder.getQueryParams().get(0).getValue());
        assertEquals("Test error description", uriBuilder.getQueryParams().get(1).getValue());
        assertEquals(
                clientOAuthSessionItem.getState(), uriBuilder.getQueryParams().get(2).getValue());
    }

    @Test
    void shouldReturn200WithErrorParamsButWithoutStateIfNotRequired() throws Exception {
        IpvSessionItem ipvSessionItemWithError = generateIpvSessionItem();
        ipvSessionItemWithError.setErrorCode(OAuth2Error.SERVER_ERROR_CODE);
        ipvSessionItemWithError.setErrorDescription("Test error description");

        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItemWithError);
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setState(null);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();

        ClientResponse clientResponse =
                toResponseClass(handler.handleRequest(event, context), ClientResponse.class);

        URIBuilder uriBuilder = new URIBuilder(clientResponse.getClient().getRedirectUrl());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, uriBuilder.getQueryParams().get(0).getValue());
        assertEquals("Test error description", uriBuilder.getQueryParams().get(1).getValue());
        assertEquals(2, uriBuilder.getQueryParams().size());
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequestForJsonRequest() throws Exception {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItem = generateIpvSessionItem();
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .build();
        var response = handler.handleRequest(event, context);

        verify(mockSessionService)
                .setAuthorizationCode(eq(ipvSessionItem), anyString(), eq("https://example.com"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_END, auditEventCaptor.getValue().getEventName());

        URI expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode)
                        .addParameter("state", "test-state")
                        .build();

        ClientResponse responseBody = OBJECT_MAPPER.convertValue(response, ClientResponse.class);
        URI actualRedirectUrl = new URI(responseBody.getClient().getRedirectUrl());
        List<NameValuePair> params = new URIBuilder(actualRedirectUrl).getQueryParams();
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertNotNull(params.get(0).getValue());
        assertEquals("test-state", params.get(1).getValue());
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));
        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .build();

        var logCollector = LogCollector.getLogCollectorFor(BuildClientOauthResponseHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> handler.handleRequest(event, context),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private IpvSessionItem generateIpvSessionItem() {
        IpvSessionItem item = new IpvSessionItem();
        item.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        item.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "test-state"));
        item.setCreationDateTime(new Date().toString());
        return item;
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());
        clientOAuthSessionItem.setResponseType("code");
        clientOAuthSessionItem.setClientId("test-client-id");
        clientOAuthSessionItem.setRedirectUri("https://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        return clientOAuthSessionItem;
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return OBJECT_MAPPER.convertValue(handlerOutput, responseClass);
    }

    private static Stream<Arguments> testParamsForSuccessfulOauthRequestForReproveIdentity() {
        return Stream.of(
                Arguments.of(Vot.P1, "P1", true),
                Arguments.of(Vot.P1, "P2", false),
                Arguments.of(Vot.P2, "P2", true),
                Arguments.of(Vot.P0, "P2", false));
    }
}
