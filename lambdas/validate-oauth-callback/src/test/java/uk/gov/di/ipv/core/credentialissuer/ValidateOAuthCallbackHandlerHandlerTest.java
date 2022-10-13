package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.CODE;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.MESSAGE;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.STATUS_CODE;

@ExtendWith(MockitoExtension.class)
class ValidateOAuthCallbackHandlerHandlerTest {

    private static final String TEST_CREDENTIAL_ISSUER_ID = "PassportIssuer";
    private static final String TEST_AUTHORIZATION_CODE = "test-authorization-code";
    private static final String TEST_OAUTH_STATE = "oauth-state";
    private static final String TEST_OAUTH_ACCESS_DENIED_ERROR = OAuth2Error.ACCESS_DENIED_CODE;
    private static final String TEST_OAUTH_SERVER_ERROR = OAuth2Error.SERVER_ERROR_CODE;
    private static final String TEST_ERROR_DESCRIPTION = "test error description";
    private static final String TEST_SESSION_ID = SecureTokenHelper.generate();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    public static final String TEST_USER_ID = "test-user-id";
    private static final TypeReference<Map<String, Object>> mapStringObject =
            new TypeReference<>() {};
    private static CredentialIssuerConfig credentialIssuerConfig;
    private static IpvSessionItem ipvSessionItem;
    @Mock private Context context;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private AuditService mockAuditService;
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

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "code",
                        "test-client-id",
                        "https://example.com/redirect",
                        "test-state",
                        TEST_USER_ID,
                        "test-journey-id",
                        false);
        CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto =
                new CredentialIssuerSessionDetailsDto(
                        TEST_CREDENTIAL_ISSUER_ID, TEST_OAUTH_STATE, TEST_AUTHORIZATION_CODE);
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
    }

    @Test
    void shouldPersistAuthorizationCodeInIPVSessionTable() throws Exception {
        when(mockConfigurationService.getCredentialIssuer(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(validInput()));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        underTest.handleRequest(inputStream, outputStream, context);

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
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() throws Exception {
        Map<String, String> inputWithoutAuthCode = validInput();
        inputWithoutAuthCode.put("authorization_code", null);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithoutAuthCode));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws Exception {
        Map<String, String> inputWithoutCriId = validInput();
        inputWithoutCriId.put("credential_issuer_id", null);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithoutCriId));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() throws Exception {
        Map<String, String> inputWithInvalidCriId = validInput();
        inputWithInvalidCriId.put("credential_issuer_id", "an invalid id");

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithInvalidCriId));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() throws Exception {
        Map<String, String> inputWithoutSessionId = validInput();
        inputWithoutSessionId.put("ipv_session_id", null);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithoutSessionId));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotPresent() throws Exception {
        Map<String, String> inputWithoutState = validInput();
        inputWithoutState.put("state", null);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithoutState));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotValid() throws Exception {
        Map<String, String> inputWithInvalidState = validInput();
        inputWithInvalidState.put("state", "not-correct-state");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithInvalidState));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_OAUTH_STATE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_OAUTH_STATE.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldUpdateSessionWithDetailsOfFailedVisitedCriOnSqsException() throws Exception {
        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(validInput()));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockConfigurationService.getCredentialIssuer(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        doThrow(new SqsException("Test sqs error"))
                .when(mockAuditService)
                .sendAuditEvent(any(AuditEvent.class));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        underTest.handleRequest(inputStream, outputStream, context);

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
    void shouldReceiveAccessDeniedJourneyResponseWhenOauthErrorAccessDenied() throws Exception {
        Map<String, String> inputWithAccessDenied = validInput();
        inputWithAccessDenied.put("error", TEST_OAUTH_ACCESS_DENIED_ERROR);
        inputWithAccessDenied.put("error_description", TEST_ERROR_DESCRIPTION);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithAccessDenied));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals("/journey/access-denied", output.get("journey"));
    }

    @Test
    void shouldReceiveJourneyErrorJourneyResponseWhenAnyOtherOauthError() throws Exception {
        Map<String, String> inputWithOtherError = validInput();
        inputWithOtherError.put("error", TEST_OAUTH_SERVER_ERROR);
        inputWithOtherError.put("error_description", TEST_ERROR_DESCRIPTION);

        InputStream inputStream =
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(inputWithOtherError));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        underTest.handleRequest(inputStream, outputStream, context);

        Map<String, Object> output =
                objectMapper.readValue(outputStream.toByteArray(), mapStringObject);

        assertEquals("/journey/error", output.get("journey"));
    }

    private Map<String, String> validInput() {
        HashMap<String, String> input = new HashMap<>();
        input.put("authorization_code", TEST_AUTHORIZATION_CODE);
        input.put("credential_issuer_id", TEST_CREDENTIAL_ISSUER_ID);
        input.put("ipv_session_id", TEST_SESSION_ID);
        input.put("redirect_uri", "redirect-uri");
        input.put("state", TEST_OAUTH_STATE);
        input.put("error", null);
        input.put("error_description", null);
        return input;
    }
}
