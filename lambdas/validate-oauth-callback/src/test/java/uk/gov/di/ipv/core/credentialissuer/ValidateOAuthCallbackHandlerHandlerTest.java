package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.validateoauthcallback.ValidateOAuthCallbackHandler;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class ValidateOAuthCallbackHandlerHandlerTest {

    private static final String TEST_CREDENTIAL_ISSUER_ID = "PassportIssuer";
    private static final String TEST_AUTHORIZATION_CODE = "test-authorization-code";
    private static final String TEST_OAUTH_STATE = "oauth-state";
    private static final String TEST_OAUTH_ACCESS_DENIED_ERROR = OAuth2Error.ACCESS_DENIED_CODE;
    private static final String TEST_OAUTH_SERVER_ERROR = OAuth2Error.SERVER_ERROR_CODE;
    private static final String TEST_ERROR_DESCRIPTION = "test error description";
    private static final String TEST_SESSION_ID = SecureTokenHelper.generate();
    public static final String TEST_USER_ID = "test-user-id";
    private static ClientSessionDetailsDto clientSessionDetailsDto;
    private static CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto;
    private static CredentialIssuerConfig credentialIssuerConfig;
    @Mock private Context context;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private AuditService mockAuditService;
    private static IpvSessionItem ipvSessionItem;
    @InjectMocks private ValidateOAuthCallbackHandler underTest;

    @BeforeAll
    static void setUp() throws URISyntaxException {
        credentialIssuerConfig =
                new CredentialIssuerConfig(
                        TEST_SESSION_ID,
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
                new CredentialIssuerSessionDetailsDto(
                        TEST_CREDENTIAL_ISSUER_ID, TEST_OAUTH_STATE, TEST_AUTHORIZATION_CODE);
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
    }

    @Test
    void shouldPersistAuthorizationCodeInIPVSessionTable() throws SqsException {
        when(mockConfigurationService.getCredentialIssuer(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                TEST_AUTHORIZATION_CODE,
                                "credential_issuer_id",
                                TEST_CREDENTIAL_ISSUER_ID,
                                "state",
                                TEST_OAUTH_STATE),
                        Map.of("ipv-session-id", TEST_SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        var auditEvents = auditEventCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, auditEvents.get(0).getEventName());

        ArgumentCaptor<IpvSessionItem> ipvSessionServiceCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(ipvSessionServiceCaptor.capture());

        assertEquals(
                TEST_AUTHORIZATION_CODE,
                ipvSessionServiceCaptor
                        .getValue()
                        .getCredentialIssuerSessionDetails()
                        .getAuthorizationCode());
    }

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("credential_issuer_id", "foo"),
                        Map.of("ipv-session-id", TEST_SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_AUTHORIZATION_CODE);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of("authorization_code", "foo"),
                        Map.of("ipv-session-id", TEST_SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet()
            throws JsonProcessingException {
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                "an invalid id",
                                "state",
                                TEST_OAUTH_STATE),
                        Map.of("ipv-session-id", TEST_SESSION_ID));
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
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
                                TEST_CREDENTIAL_ISSUER_ID),
                        Map.of());
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
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
                                TEST_CREDENTIAL_ISSUER_ID),
                        Map.of("ipv-session-id", TEST_SESSION_ID));
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_OAUTH_STATE);
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotValid() throws JsonProcessingException {
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                "foo",
                                "credential_issuer_id",
                                TEST_CREDENTIAL_ISSUER_ID,
                                "state",
                                "not-correct-state"),
                        Map.of("ipv-session-id", TEST_SESSION_ID));
        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.INVALID_OAUTH_STATE);
    }

    @Test
    void shouldUpdateSessionWithDetailsOfFailedVisitedCriOnSqsException() throws SqsException {
        when(mockConfigurationService.getCredentialIssuer(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "authorization_code",
                                TEST_AUTHORIZATION_CODE,
                                "credential_issuer_id",
                                TEST_CREDENTIAL_ISSUER_ID,
                                "state",
                                TEST_OAUTH_STATE),
                        Map.of("ipv-session-id", TEST_SESSION_ID));

        doThrow(new SqsException("Test sqs error"))
                .when(mockAuditService)
                .sendAuditEvent(any(AuditEvent.class));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        underTest.handleRequest(input, context);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, updatedIpvSessionItem.getVisitedCredentialIssuerDetails().size());
        assertEquals(
                TEST_CREDENTIAL_ISSUER_ID,
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
    void shouldReceiveAccessDeniedJourneyResponseWhenOauthErrorAccessDenied()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "credential_issuer_id",
                                TEST_CREDENTIAL_ISSUER_ID,
                                "error",
                                TEST_OAUTH_ACCESS_DENIED_ERROR,
                                "error_description",
                                TEST_ERROR_DESCRIPTION),
                        Map.of("ipv-session-id", TEST_SESSION_ID));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/access-denied", responseBody.get("journey"));
    }

    @Test
    void shouldReceiveJourneyErrorJourneyResponseWhenAnyOtherOauthError()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(
                        Map.of(
                                "credential_issuer_id",
                                TEST_CREDENTIAL_ISSUER_ID,
                                "error",
                                TEST_OAUTH_SERVER_ERROR,
                                "error_description",
                                TEST_ERROR_DESCRIPTION),
                        Map.of("ipv-session-id", TEST_SESSION_ID));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/error", responseBody.get("journey"));
    }

    private Map getResponseBodyAsMap(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), Map.class);
    }

    private void assert400Response(
            APIGatewayProxyResponseEvent response, ErrorResponse errorResponse)
            throws JsonProcessingException {
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(errorResponse.getCode(), responseBody.get("error"));
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
}
