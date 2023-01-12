package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
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
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
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
    private static final String TEST_REDIRECT_URI = "https://redirect.example.com";
    private static final String TEST_OAUTH_ACCESS_DENIED_ERROR = OAuth2Error.ACCESS_DENIED_CODE;
    private static final String TEST_OAUTH_SERVER_ERROR = OAuth2Error.SERVER_ERROR_CODE;
    private static final String TEST_ERROR_DESCRIPTION = "test error description";
    private static final String TEST_SESSION_ID = SecureTokenHelper.generate();
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String CODE = "code";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";
    private static final String TYPE = "type";
    private static final String PAGE = "page";
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

        Map<String, Object> output =
                underTest.handleRequest(validCredentialIssuerRequestDto(), context);

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

        assertEquals("/journey/cri/access-token", output.get("journey"));
    }

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() {
        CredentialIssuerRequestDto credentialIssuerRequestWithoutAuthCode =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithoutAuthCode.setAuthorizationCode(null);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithoutAuthCode, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() {
        CredentialIssuerRequestDto credentialIssuerRequestWithoutCriId =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithoutCriId.setCredentialIssuerId(null);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithoutCriId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() {
        CredentialIssuerRequestDto credentialIssuerRequestWithInvalidCriId =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithInvalidCriId.setCredentialIssuerId("an invalid id");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithInvalidCriId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() {
        CredentialIssuerRequestDto credentialIssuerRequestWithoutSessionId =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithoutSessionId.setIpvSessionId(null);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithoutSessionId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotPresentInRequest() {
        CredentialIssuerRequestDto credentialIssuerRequestWithoutState =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithoutState.setState(null);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithoutState, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseWithPageIdIfOAuthStateNotPresentInSession() {
        CredentialIssuerRequestDto credentialIssuerRequest = validCredentialIssuerRequestDto();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setCredentialIssuerSessionDetails(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output = underTest.handleRequest(credentialIssuerRequest, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals("pyi-technical-unrecoverable", output.get(PAGE));
        assertEquals("error", output.get(TYPE));
    }

    @Test
    void shouldReceive400ResponseWithPageIdIfOAuthStateNotValid() {
        CredentialIssuerRequestDto credentialIssuerRequestWithInvalidState =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithInvalidState.setState("not-correct-state");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithInvalidState, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals("pyi-technical-unrecoverable", output.get(PAGE));
        assertEquals("error", output.get(TYPE));
    }

    @Test
    void shouldUpdateSessionWithDetailsOfFailedVisitedCriOnSqsException() throws Exception {
        when(mockConfigurationService.getCredentialIssuer(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        doThrow(new SqsException("Test sqs error"))
                .when(mockAuditService)
                .sendAuditEvent(any(AuditEvent.class));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        underTest.handleRequest(validCredentialIssuerRequestDto(), context);

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
    void shouldReceiveAccessDeniedJourneyResponseWhenOauthErrorAccessDenied() {
        CredentialIssuerRequestDto credentialIssuerRequestWithAccessDenied =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithAccessDenied.setError(TEST_OAUTH_ACCESS_DENIED_ERROR);
        credentialIssuerRequestWithAccessDenied.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithAccessDenied, context);

        assertEquals("/journey/access-denied", output.get("journey"));
    }

    @Test
    void shouldReceiveJourneyErrorJourneyResponseWhenAnyOtherOauthError() {
        CredentialIssuerRequestDto credentialIssuerRequestWithOtherError =
                validCredentialIssuerRequestDto();
        credentialIssuerRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        credentialIssuerRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(credentialIssuerRequestWithOtherError, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    private CredentialIssuerRequestDto validCredentialIssuerRequestDto() {
        return new CredentialIssuerRequestDto(
                TEST_AUTHORIZATION_CODE,
                TEST_CREDENTIAL_ISSUER_ID,
                TEST_SESSION_ID,
                TEST_REDIRECT_URI,
                TEST_OAUTH_STATE,
                null,
                null,
                TEST_IP_ADDRESS);
    }
}
