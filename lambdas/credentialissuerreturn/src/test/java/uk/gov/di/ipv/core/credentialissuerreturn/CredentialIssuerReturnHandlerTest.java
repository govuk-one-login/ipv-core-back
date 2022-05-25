package uk.gov.di.ipv.core.credentialissuerreturn;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
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
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerReturnHandlerTest {

    private static final String TEST_VERIFIABLE_CREDENTIAL = "A.VERIFIABLE.CREDENTIAL";
    public static final String OAUTH_STATE = "oauth-state";

    @Mock private Context context;

    @Captor private ArgumentCaptor<CredentialIssuerRequestDto> requestDto;

    @Captor private ArgumentCaptor<String> verifiableCredentialCaptor;

    @Mock private CredentialIssuerService credentialIssuerService;

    @Mock private AuditService auditService;

    @Mock private ConfigurationService configurationService;

    @Mock private SignedJWT signedJWT;

    @Mock private VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;

    @Mock private IpvSessionService ipvSessionService;

    @Mock private IpvSessionItem ipvSessionItem;

    @InjectMocks private CredentialIssuerReturnHandler handler;

    private static CredentialIssuerConfig passportIssuer;
    private static ClientSessionDetailsDto clientSessionDetailsDto;
    private static CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto;
    private final String authorization_code = "bar";
    private final String sessionId = UUID.randomUUID().toString();
    private final String passportIssuerId = "PassportIssuer";

    @BeforeAll
    static void setUp() throws URISyntaxException {
        passportIssuer =
                new CredentialIssuerConfig(
                        "PassportIssuer",
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
                        "test-user-id",
                        false);

        credentialIssuerSessionDetailsDto =
                new CredentialIssuerSessionDetailsDto("PassportIssuer", OAUTH_STATE);
    }

    @Test
    void shouldReceive200AndJourneyResponseOnSuccessfulRequest()
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

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), eq(passportIssuer)))
                .thenReturn(new BearerAccessToken());

        when(credentialIssuerService.getVerifiableCredential(any(), any())).thenReturn(signedJWT);

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        when(ipvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);

        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        verify(auditService).sendAuditEvent(AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED);

        verify(auditService)
                .sendAuditEvent(AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED);

        verify(auditService).sendAuditEvent(AuditEventTypes.IPV_VC_RECEIVED);

        verify(verifiableCredentialJwtValidator)
                .validate(signedJWT, passportIssuer, "test-user-id");

        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/next", responseBody.get("journey"));
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

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), eq(passportIssuer)))
                .thenReturn(accessToken);

        when(credentialIssuerService.getVerifiableCredential(accessToken, passportIssuer))
                .thenReturn(SignedJWT.parse(SIGNED_VC_1));

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        when(ipvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);

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

        CredentialIssuerRequestDto value = requestDto.getValue();
        assertEquals(sessionId, value.getIpvSessionId());
        assertEquals(passportIssuerId, value.getCredentialIssuerId());
        assertEquals(authorization_code, value.getAuthorizationCode());

        verify(credentialIssuerService)
                .persistUserCredentials(verifiableCredentialCaptor.capture(), any());
        assertEquals(SIGNED_VC_1, verifiableCredentialCaptor.getValue());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());

        verifyNoInteractions(context);
    }

    @Test
    void shouldReceive500ResponseCodeIfCredentialIssuerServiceThrowsException()
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

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), eq(passportIssuer)))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_BAD_REQUEST,
                                new ErrorObject(
                                        OAuth2Error.SERVER_ERROR_CODE,
                                        ErrorResponse.INVALID_TOKEN_REQUEST.getMessage())));

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_SERVER_ERROR, statusCode);
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
        verifyNoInteractions(context);
    }

    @Test
    void shouldReturn500IfCredentialIssuerServiceGetCredentialThrows()
            throws JsonProcessingException {
        when(credentialIssuerService.exchangeCodeForToken(any(), any()))
                .thenReturn(new BearerAccessToken());
        when(credentialIssuerService.getVerifiableCredential(any(), any()))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                new ErrorObject(
                                        OAuth2Error.SERVER_ERROR_CODE,
                                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER
                                                .getMessage())));

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

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

        assertEquals(HTTPResponse.SC_SERVER_ERROR, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, getResponseBodyAsMap(response).get("error"));
    }

    @Test
    void shouldThrow500IfVCFailsValidation() throws Exception {
        BearerAccessToken accessToken = mock(BearerAccessToken.class);

        when(credentialIssuerService.exchangeCodeForToken(requestDto.capture(), eq(passportIssuer)))
                .thenReturn(accessToken);

        when(credentialIssuerService.getVerifiableCredential(accessToken, passportIssuer))
                .thenReturn(SignedJWT.parse(SIGNED_VC_1));

        when(configurationService.getCredentialIssuer("PassportIssuer")).thenReturn(passportIssuer);

        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        when(ipvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);

        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(credentialIssuerSessionDetailsDto);

        doThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                new ErrorObject(
                                        OAuth2Error.SERVER_ERROR_CODE,
                                        ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL
                                                .getMessage())))
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

        assertEquals(HTTPResponse.SC_SERVER_ERROR, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, getResponseBodyAsMap(response).get("error"));
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
        assertEquals(errorResponse.getCode(), responseBody.get("code"));
        verifyNoInteractions(context, credentialIssuerService);
    }
}
