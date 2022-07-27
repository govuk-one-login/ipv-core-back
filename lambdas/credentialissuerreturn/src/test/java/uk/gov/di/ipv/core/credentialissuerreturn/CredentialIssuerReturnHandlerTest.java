package uk.gov.di.ipv.core.credentialissuerreturn;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerV2Service;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRACT_INDICATORS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerReturnHandlerTest {

    public static final String OAUTH_STATE = "oauth-state";
    public static final String CREDENTIAL_ISSUER_ID = "PassportIssuer";
    public static final String TEST_USER_ID = "test-user-id";

    @Mock private Context context;

    @Captor private ArgumentCaptor<CredentialIssuerRequestDto> requestDto;

    @Captor private ArgumentCaptor<String> verifiableCredentialCaptor;

    @Mock private CredentialIssuerService credentialIssuerService;

    @Mock private CredentialIssuerV2Service credentialIssuerV2Service;

    @Mock private AuditService auditService;

    @Mock private static ConfigurationService configurationService;

    @Mock private SignedJWT signedJWT;

    @Mock private VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;

    @Mock private IpvSessionService ipvSessionService;

    @Mock private IpvSessionItem ipvSessionItem;

    @InjectMocks private CredentialIssuerReturnHandler handler;

    private static CredentialIssuerConfig passportIssuer;
    private static ClientSessionDetailsDto clientSessionDetailsDto;
    private static CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto;
    private static AuditEventUser auditEventUser;
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
                        "test-audience");

        clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "code",
                        "test-client-id",
                        "https://example.com/redirect",
                        "test-state",
                        TEST_USER_ID,
                        false);

        credentialIssuerSessionDetailsDto =
                new CredentialIssuerSessionDetailsDto(CREDENTIAL_ISSUER_ID, OAUTH_STATE);

        auditEventUser = new AuditEventUser(TEST_USER_ID, sessionId);
    }

    @Test
    void shouldReceive200AndJourneyResponseOnSuccessfulRequest()
            throws JsonProcessingException, SqsException, ParseException {

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

        when(credentialIssuerService.exchangeCodeForToken(
                        requestDto.capture(), eq(passportIssuer), eq(testApiKey)))
                .thenReturn(new BearerAccessToken());

        when(credentialIssuerService.getVerifiableCredential(any(), any(), anyString()))
                .thenReturn(SignedJWT.parse(SIGNED_VC_1));

        mockServiceCallsAndSessionItem();

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var auditEvents = auditEventCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, auditEvents.get(1).getEventName());

        verify(verifiableCredentialJwtValidator)
                .validate(any(SignedJWT.class), eq(passportIssuer), eq(TEST_USER_ID));

        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/cri/validate/" + CREDENTIAL_ISSUER_ID, responseBody.get("journey"));
    }

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("credential_issuer_id", "foo"), Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_AUTHORIZATION_CODE);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("authorization_code", "foo"), Map.of("ipv-session-id", sessionId));

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet()
            throws JsonProcessingException {
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                "an invalid id",
                                "state",
                                OAUTH_STATE),
                        Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assert400Response(response, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of());
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_IPV_SESSION_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId),
                        Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response =
                new CredentialIssuerReturnHandler(
                                credentialIssuerService,
                                credentialIssuerV2Service,
                                configurationService,
                                ipvSessionService,
                                auditService,
                                verifiableCredentialJwtValidator)
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_OAUTH_STATE);
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotValid() throws JsonProcessingException {
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                passportIssuerId,
                                "state",
                                "not-correct-state"),
                        Map.of("ipv-session-id", sessionId));
        APIGatewayProxyResponseEvent response =
                new CredentialIssuerReturnHandler(
                                credentialIssuerService,
                                credentialIssuerV2Service,
                                configurationService,
                                ipvSessionService,
                                auditService,
                                verifiableCredentialJwtValidator)
                        .handleRequest(input, context);
        assert400Response(response, ErrorResponse.INVALID_OAUTH_STATE);
    }

    @Test
    void shouldReceive200ResponseCodeIfAllRequestParametersValid() throws Exception {
        BearerAccessToken accessToken = mock(BearerAccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                        requestDto.capture(), eq(passportIssuer), eq(testApiKey)))
                .thenReturn(accessToken);

        when(ipvSessionService.getUserId(anyString())).thenReturn(TEST_USER_ID);

        when(credentialIssuerService.getVerifiableCredential(
                        accessToken, passportIssuer, testApiKey))
                .thenReturn(SignedJWT.parse(SIGNED_VC_1));

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

        CredentialIssuerRequestDto value = requestDto.getValue();
        assertEquals(sessionId, value.getIpvSessionId());
        assertEquals(passportIssuerId, value.getCredentialIssuerId());
        assertEquals(authorization_code, value.getAuthorizationCode());

        verify(credentialIssuerService)
                .persistUserCredentials(verifiableCredentialCaptor.capture(), any());
        assertEquals(SIGNED_VC_1, verifiableCredentialCaptor.getValue());
        verify(credentialIssuerV2Service)
                .persistUserCredentials(
                        verifiableCredentialCaptor.capture(),
                        eq(passportIssuerId),
                        eq(TEST_USER_ID));
        assertEquals(SIGNED_VC_1, verifiableCredentialCaptor.getValue());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
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
                        requestDto.capture(), eq(passportIssuer), eq(testApiKey)))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST));

        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);
        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/error", responseBody.get("journey"));
    }

    @Test
    void shouldReturn200ErrorJourneyResponseIfCredentialIssuerServiceGetCredentialThrows()
            throws JsonProcessingException {
        when(credentialIssuerService.exchangeCodeForToken(any(), any(), anyString()))
                .thenReturn(new BearerAccessToken());
        when(credentialIssuerService.getVerifiableCredential(any(), any(), anyString()))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));

        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);
        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);

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

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        assertEquals("/journey/error", getResponseBodyAsMap(response).get("journey"));
    }

    @Test
    void shouldReturrn200ErrorJourneyIfVCFailsValidation() throws Exception {
        BearerAccessToken accessToken = mock(BearerAccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                        requestDto.capture(), eq(passportIssuer), eq(testApiKey)))
                .thenReturn(accessToken);

        when(credentialIssuerService.getVerifiableCredential(
                        accessToken, passportIssuer, testApiKey))
                .thenReturn(SignedJWT.parse(SIGNED_VC_1));

        mockServiceCallsAndSessionItem();

        doThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(verifiableCredentialJwtValidator)
                .validate(any(), any(), any());

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

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        assertEquals("/journey/error", getResponseBodyAsMap(response).get("journey"));
    }

    @Test
    void shouldReceive200ResponseCodeAndSendIpvVcReceivedAuditEvent() throws Exception {
        BearerAccessToken accessToken = mock(BearerAccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                        requestDto.capture(), eq(passportIssuer), eq(testApiKey)))
                .thenReturn(accessToken);

        when(credentialIssuerService.getVerifiableCredential(
                        accessToken, passportIssuer, testApiKey))
                .thenReturn(SignedJWT.parse(SIGNED_CONTRACT_INDICATORS));

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
        verify(auditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var auditEvents = auditEventCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, auditEvents.get(1).getEventName());

        assertEquals(testComponentId, auditEvents.get(0).getComponentId());
        AuditEventUser auditEventUser = auditEvents.get(0).getUser();
        assertEquals(TEST_USER_ID, auditEventUser.getUserId());
        assertEquals(sessionId, auditEventUser.getSessionId());

        AuditExtensionsVcEvidence auditExtensionsVcEvidence =
                (AuditExtensionsVcEvidence) auditEvents.get(1).getExtensions();
        assertEquals("https://issuer.example.com", auditExtensionsVcEvidence.getIss());
        JsonNode evidenceItem = auditExtensionsVcEvidence.getEvidence().get(0);
        assertEquals("IdentityCheck", evidenceItem.get("type").asText());
        assertEquals("DSJJSEE29392", evidenceItem.get("txn").asText());
        assertEquals("0", evidenceItem.get("verificationScore").asText());
        assertEquals("[ \"A02\", \"A03\" ]", evidenceItem.get("ci").toPrettyString());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReceive200ResponseCodeAndSendIpvVcReceivedAuditEventWhenVcEvidenceIsMissing()
            throws Exception {
        BearerAccessToken accessToken = mock(BearerAccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(
                        requestDto.capture(), eq(passportIssuer), eq(testApiKey)))
                .thenReturn(accessToken);

        when(credentialIssuerService.getVerifiableCredential(
                        accessToken, passportIssuer, testApiKey))
                .thenReturn(SignedJWT.parse(SIGNED_ADDRESS_VC));

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

        ArgumentCaptor<AuditEvent> argumentCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(argumentCaptor.capture());
        AuditEvent event = argumentCaptor.getAllValues().get(1);
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, event.getEventName());

        assertEquals(testComponentId, event.getComponentId());

        AuditEventUser auditEventUser = event.getUser();
        assertEquals(TEST_USER_ID, auditEventUser.getUserId());
        assertEquals(sessionId, auditEventUser.getSessionId());

        AuditExtensionsVcEvidence auditExtensionsVcEvidence =
                (AuditExtensionsVcEvidence) argumentCaptor.getValue().getExtensions();
        assertEquals(
                "https://staging-di-ipv-cri-address-front.london.cloudapps.digital",
                auditExtensionsVcEvidence.getIss());
        assertNull(auditExtensionsVcEvidence.getEvidence());
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    private void mockServiceCallsAndSessionItem() {
        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(passportIssuer);

        when(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn(testComponentId);

        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionService.getUserId(anyString())).thenReturn(TEST_USER_ID);

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

        doThrow(new SqsException("Test sqs error"))
                .when(auditService)
                .sendAuditEvent(any(AuditEvent.class));

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        assertEquals("/journey/error", getResponseBodyAsMap(response).get("journey"));
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
