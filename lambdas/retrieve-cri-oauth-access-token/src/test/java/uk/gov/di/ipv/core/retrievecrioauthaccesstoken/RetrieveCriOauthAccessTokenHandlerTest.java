package uk.gov.di.ipv.core.retrievecrioauthaccesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class RetrieveCriOauthAccessTokenHandlerTest {

    public static final String OAUTH_STATE = "oauth-state";
    public static final String CREDENTIAL_ISSUER_ID = "PassportIssuer";
    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_AUTH_CODE = "test-auth-code";

    @Mock private Context context;
    @Captor private ArgumentCaptor<String> authCode;
    @Captor private ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor;
    @Mock private CredentialIssuerService credentialIssuerService;
    @Mock private AuditService auditService;
    @Mock private static ConfigurationService configurationService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private IpvSessionItem ipvSessionItem;
    @InjectMocks private RetrieveCriOauthAccessTokenHandler handler;

    private static CredentialIssuerConfig passportIssuer;
    private static ClientSessionDetailsDto clientSessionDetailsDto;
    private static CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto;
    private static final String authorization_code = "bar";
    private static final String sessionId = SecureTokenHelper.generate();
    private static final String passportIssuerId = CREDENTIAL_ISSUER_ID;
    private static final String testApiKey = "test-api-key";
    private static final String testComponentId = "http://ipv-core-test.example.com";

    @BeforeAll
    static void setUp() throws URISyntaxException {

        passportIssuer =
                new CredentialIssuerConfig(
                        CREDENTIAL_ISSUER_ID,
                        "any",
                        new URI("http://www.example.com"),
                        new URI("http://www.example.com/credential"),
                        new URI("http://www.example.com/authorize"),
                        "ipv-core",
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "test-audience",
                        new URI("http://www.example.com/credential-issuers/callback/criId"));

        clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "code",
                        "test-client-id",
                        "https://example.com/redirect",
                        "test-state",
                        TEST_USER_ID,
                        "test-journey-id",
                        false);

        credentialIssuerSessionDetailsDto =
                new CredentialIssuerSessionDetailsDto(CREDENTIAL_ISSUER_ID, OAUTH_STATE);
        credentialIssuerSessionDetailsDto.setAuthorizationCode(TEST_AUTH_CODE);
    }

    @Test
    void shouldReceive200AndJourneyResponseOnSuccessfulRequest()
            throws JsonProcessingException, SqsException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(Collections.emptyMap(), Map.of("ipv-session-id", sessionId));

        JSONObject testCredential = new JSONObject();
        testCredential.appendField("foo", "bar");

        when(credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, passportIssuer, testApiKey))
                .thenReturn(new BearerAccessToken());

        mockServiceCallsAndSessionItem();

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        var auditEvents = auditEventCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_CRI_ACCESS_TOKEN_EXCHANGED, auditEvents.get(0).getEventName());

        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/next", responseBody.get("journey"));
    }

    @Test
    void shouldUseAuthCodeFromRequestIfNotSavedInSession() {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "request_authorization_code",
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));

        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);
        when(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn(testComponentId);
        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("someIpvSessionId");
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        credentialIssuerSessionDetailsDto.setAuthorizationCode(null);
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        when(credentialIssuerService.exchangeCodeForToken(
                        authCode.capture(), eq(passportIssuer), eq(testApiKey)))
                .thenReturn(new BearerAccessToken());

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        Integer statusCode = response.getStatusCode();
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("request_authorization_code", authCode.getValue());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals("RETRIEVE_CRI_OAUTH_ACCESS_TOKEN", updatedIpvSessionItem.getUserState());
    }

    @Test
    void shouldReceive200ErrorJourneyResponseIfCredentialIssuerServiceThrowsException()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));

        when(credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, passportIssuer, testApiKey))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST));

        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);
        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/error", responseBody.get("journey"));
    }

    @Test
    void shouldReceive200ResponseCodeAndSendIpvVcReceivedAuditEvent() throws Exception {
        BearerAccessToken accessToken = mock(BearerAccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, passportIssuer, testApiKey))
                .thenReturn(accessToken);

        mockServiceCallsAndSessionItem();

        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                authorization_code,
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        var auditEvents = auditEventCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_CRI_ACCESS_TOKEN_EXCHANGED, auditEvents.get(0).getEventName());

        assertEquals(testComponentId, auditEvents.get(0).getComponentId());
        AuditEventUser auditEventUser = auditEvents.get(0).getUser();
        assertEquals(TEST_USER_ID, auditEventUser.getUserId());
        assertEquals(sessionId, auditEventUser.getSessionId());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    private void mockServiceCallsAndSessionItem() {
        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);

        when(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn(testComponentId);

        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        when(ipvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);

        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);
    }

    @Test
    void shouldReceive200ErrorJourneyResponseIfSqsExceptionIsThrown()
            throws JsonProcessingException, SqsException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));

        JSONObject testCredential = new JSONObject();
        testCredential.appendField("foo", "bar");

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);
        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);
        doThrow(new SqsException("Test sqs error"))
                .when(auditService)
                .sendAuditEvent(any(AuditEvent.class));

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        assertEquals("/journey/error", getResponseBodyAsMap(response).get("journey"));
    }

    @Test
    void shouldUpdateSessionWithDetailsOfVisitedCri() {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));

        JSONObject testCredential = new JSONObject();
        testCredential.appendField("foo", "bar");

        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);

        when(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn(testComponentId);

        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        when(credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, passportIssuer, testApiKey))
                .thenReturn(new BearerAccessToken());

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("someIpvSessionId");
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        handler.handleRequest(input, context);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, updatedIpvSessionItem.getVisitedCredentialIssuerDetails().size());
        assertEquals(
                passportIssuerId,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getCriId());
        assertTrue(
                updatedIpvSessionItem
                        .getVisitedCredentialIssuerDetails()
                        .get(0)
                        .isReturnedWithVc());
        assertNull(
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getOauthError());
    }

    @Test
    void shouldUpdateSessionWithDetailsOfFailedCriVisitOnCredentialIssuerException() {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));

        JSONObject testCredential = new JSONObject();
        testCredential.appendField("foo", "bar");

        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);

        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        when(credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, passportIssuer, testApiKey))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("someIpvSessionId");
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        handler.handleRequest(input, context);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, updatedIpvSessionItem.getVisitedCredentialIssuerDetails().size());
        assertEquals(
                passportIssuerId,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getCriId());
        assertFalse(
                updatedIpvSessionItem
                        .getVisitedCredentialIssuerDetails()
                        .get(0)
                        .isReturnedWithVc());
        assertEquals(
                OAuth2Error.SERVER_ERROR_CODE,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getOauthError());
    }

    @Test
    void shouldUpdateSessionWithDetailsOfFailedVisitedCriOnSqsException() throws SqsException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));

        JSONObject testCredential = new JSONObject();
        testCredential.appendField("foo", "bar");

        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);

        when(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn(testComponentId);

        doThrow(new SqsException("Test sqs error"))
                .when(auditService)
                .sendAuditEvent(any(AuditEvent.class));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("someIpvSessionId");
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        handler.handleRequest(input, context);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, updatedIpvSessionItem.getVisitedCredentialIssuerDetails().size());
        assertEquals(
                passportIssuerId,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getCriId());
        assertFalse(
                updatedIpvSessionItem
                        .getVisitedCredentialIssuerDetails()
                        .get(0)
                        .isReturnedWithVc());
        assertEquals(
                OAuth2Error.SERVER_ERROR_CODE,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getOauthError());
    }

    private Map getResponseBodyAsMap(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), Map.class);
    }

    private APIGatewayProxyRequestEvent createRequestEvent(
            Map<String, String> body, Map<String, String> headers) {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody(
                body.keySet().stream()
                        .map(key -> key + "=" + body.get(key))
                        .collect(Collectors.joining("&")));
        input.setHeaders(headers);
        return input;
    }

    private void assert400Response(
            APIGatewayProxyResponseEvent response, ErrorResponse errorResponse)
            throws JsonProcessingException {
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(errorResponse.getCode(), responseBody.get("error"));
        verifyNoInteractions(credentialIssuerService);
    }
}
