package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.validateoauthcallback.ValidateOAuthCallbackHandler;
import uk.gov.di.ipv.core.validateoauthcallback.dto.CriCallbackRequest;

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
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DRIVING_LICENCE_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;

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
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
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
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private AuditService mockAuditService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    private ValidateOAuthCallbackHandler underTest;
    private CriOAuthSessionItem criOAuthSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeEach
    void setUpBeforeEach() throws URISyntaxException {
        when(mockConfigService.getSsmParameter(COMPONENT_ID)).thenReturn("audience.for.clients");

        credentialIssuerConfig = createCriConfig("cri.iss.com");

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setCriOAuthSessionId(TEST_OAUTH_STATE);
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .build();

        criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(TEST_OAUTH_STATE)
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .criId(TEST_CREDENTIAL_ISSUER_ID)
                        .accessToken("testAccessToken")
                        .authorizationCode(TEST_AUTHORIZATION_CODE)
                        .build();

        underTest =
                new ValidateOAuthCallbackHandler(
                        mockConfigService,
                        mockIpvSessionService,
                        mockAuditService,
                        mockCriOAuthSessionService,
                        mockClientOAuthSessionDetailsService);
    }

    @Test
    void shouldPersistAuthorizationCodeInCriOAuthSessionTable() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output = underTest.handleRequest(validCriCallbackRequest(), context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        var auditEvents = auditEventCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, auditEvents.get(0).getEventName());

        ArgumentCaptor<CriOAuthSessionItem> criOAuthSessionCaptor =
                ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockCriOAuthSessionService)
                .updateCriOAuthSessionItem(criOAuthSessionCaptor.capture());

        assertEquals(
                TEST_AUTHORIZATION_CODE, criOAuthSessionCaptor.getValue().getAuthorizationCode());

        ArgumentCaptor<CriOAuthSessionItem> criOAuthSessionServiceCaptor =
                ArgumentCaptor.forClass(CriOAuthSessionItem.class);
        verify(mockCriOAuthSessionService)
                .updateCriOAuthSessionItem(criOAuthSessionServiceCaptor.capture());

        assertEquals(
                TEST_AUTHORIZATION_CODE,
                criOAuthSessionServiceCaptor.getValue().getAuthorizationCode());

        assertEquals("/journey/cri/access-token", output.get("journey"));
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
        verify(mockCriOAuthSessionService, times(1)).updateCriOAuthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfAuthorizationCodeNotPresent() {
        CriCallbackRequest criCallbackRequestWithoutAuthCode = validCriCallbackRequest();
        criCallbackRequestWithoutAuthCode.setAuthorizationCode(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutAuthCode, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() {
        CriCallbackRequest criCallbackRequestWithoutCriId = validCriCallbackRequest();
        criCallbackRequestWithoutCriId.setCredentialIssuerId(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutCriId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() {
        CriCallbackRequest criCallbackRequestWithInvalidCriId = validCriCallbackRequest();
        criCallbackRequestWithInvalidCriId.setCredentialIssuerId("an invalid id");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithInvalidCriId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReceive400ResponseCodeIfCriOAuthStateAndSessionNotPresent() {
        CriCallbackRequest criCallbackRequestWithoutSessionId = validCriCallbackRequest();
        criCallbackRequestWithoutSessionId.setIpvSessionId(null);
        criCallbackRequestWithoutSessionId.setState(null);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutSessionId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceiveAccessDeniedJourneyIfSessionNotPresentForCriOAuthSession() {
        CriCallbackRequest criCallbackRequestWithoutSessionId = validCriCallbackRequest();
        criCallbackRequestWithoutSessionId.setIpvSessionId(null);
        criCallbackRequestWithoutSessionId.setState(TEST_OAUTH_STATE);

        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutSessionId, context);

        assertEquals(HttpStatus.SC_UNAUTHORIZED, output.get(STATUS_CODE));
        assertEquals("pyi-timeout-recoverable", output.get(PAGE));
        assertEquals("error", output.get(TYPE));
        assertEquals(clientOAuthSessionItem.getClientOAuthSessionId(), output.get("clientOAuthSessionId"));
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotPresentInRequest() {
        CriCallbackRequest criCallbackRequestWithoutState = validCriCallbackRequest();
        criCallbackRequestWithoutState.setState(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutState, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseWithAttemptRecoveryPageIfOAuthStateNotPresentInSession() {
        CriCallbackRequest criCallbackRequest = validCriCallbackRequest();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setClientOAuthSessionId(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output = underTest.handleRequest(criCallbackRequest, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals("pyi-attempt-recovery", output.get(PAGE));
        assertEquals("error", output.get(TYPE));
    }

    @Test
    void shouldReceive400ResponseWithAttemptRecoveryPageIfOAuthStateNotValid() {
        CriCallbackRequest criCallbackRequestWithInvalidState = validCriCallbackRequest();
        criCallbackRequestWithInvalidState.setState("not-correct-state");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithInvalidState, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals("pyi-attempt-recovery", output.get(PAGE));
        assertEquals("error", output.get(TYPE));
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldUpdateSessionWithDetailsOfFailedVisitedCriOnSqsException() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        doThrow(new SqsException("Test sqs error"))
                .when(mockAuditService)
                .sendAuditEvent(any(AuditEvent.class));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        underTest.handleRequest(validCriCallbackRequest(), context);

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
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceiveAccessDeniedJourneyResponseWhenOauthErrorAccessDeniedAndOnlyPassportEnabled()
            throws URISyntaxException {
        CriCallbackRequest criCallbackRequestWithAccessDenied = validCriCallbackRequest();
        criCallbackRequestWithAccessDenied.setError(TEST_OAUTH_ACCESS_DENIED_ERROR);
        criCallbackRequestWithAccessDenied.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockConfigService.isEnabled(PASSPORT_CRI)).thenReturn(true);

        when(mockConfigService.isEnabled(DRIVING_LICENCE_CRI)).thenReturn(false);
        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithAccessDenied, context);

        assertEquals("/journey/access-denied", output.get("journey"));
    }

    @Test
    void
            shouldReceiveAccessDeniedMultiJourneyResponseWhenOauthErrorAccessDeniedAndBothPassportAndDrivingLicenceEnabled()
                    throws URISyntaxException {
        CriCallbackRequest criCallbackRequestWithAccessDenied = validCriCallbackRequest();
        criCallbackRequestWithAccessDenied.setError(TEST_OAUTH_ACCESS_DENIED_ERROR);
        criCallbackRequestWithAccessDenied.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockConfigService.isEnabled(PASSPORT_CRI)).thenReturn(true);

        when(mockConfigService.isEnabled(DRIVING_LICENCE_CRI)).thenReturn(true);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithAccessDenied, context);

        assertEquals("/journey/access-denied-multi-doc", output.get("journey"));
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceiveTemporarilyUnavailableJourneyResponseWhenOauthErrorTemporarilyUnavailable() {
        CriCallbackRequest criCallbackRequestWithAccessDenied = validCriCallbackRequest();
        criCallbackRequestWithAccessDenied.setError(OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE);
        criCallbackRequestWithAccessDenied.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithAccessDenied, context);

        assertEquals("/journey/temporarily-unavailable", output.get("journey"));
        verify(mockCriOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceiveJourneyErrorJourneyResponseWhenAnyOtherOauthError() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithOtherError, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    @Test
    void shouldAttemptRecoveryErrorResponseWhenOauthSessionIsNull() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        ipvSessionItem.setCriOAuthSessionId(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithOtherError, context);

        assertEquals("error", output.get("type"));
        assertEquals("pyi-attempt-recovery", output.get("page"));
        assertEquals(400, output.get("statusCode"));
    }

    @Test
    void shouldAttemptRecoveryErrorResponseWhenOauthSessionIsForDifferentCri() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        criOAuthSessionItem.setCriId("test");
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithOtherError, context);

        assertEquals("error", output.get("type"));
        assertEquals("pyi-attempt-recovery", output.get("page"));
        assertEquals(400, output.get("statusCode"));
    }

    @Test
    void shouldNotUpdateSessionOnAttemptRecoveryError_whenCriIdNotMatchedWithRequest() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        criOAuthSessionItem.setCriId("test");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService, times(0))
                .updateIpvSession(ipvSessionItemArgumentCaptor.capture());

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithOtherError, context);

        assertEquals("error", output.get("type"));
        assertEquals("pyi-attempt-recovery", output.get("page"));
        assertEquals(400, output.get("statusCode"));
    }

    @Test
    void shouldNotUpdateSessionOnAttemptRecoveryError_whenIpvSessionNotHaveCriSessionId() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        ipvSessionItem.setCriOAuthSessionId(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService, times(0))
                .updateIpvSession(ipvSessionItemArgumentCaptor.capture());

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithOtherError, context);

        assertEquals("error", output.get("type"));
        assertEquals("pyi-attempt-recovery", output.get("page"));
        assertEquals(400, output.get("statusCode"));
    }

    private CriCallbackRequest validCriCallbackRequest() {
        return new CriCallbackRequest(
                TEST_AUTHORIZATION_CODE,
                TEST_CREDENTIAL_ISSUER_ID,
                TEST_SESSION_ID,
                TEST_REDIRECT_URI,
                TEST_OAUTH_STATE,
                null,
                null,
                TEST_IP_ADDRESS);
    }

    private CredentialIssuerConfig createCriConfig(String criIss) throws URISyntaxException {
        return new CredentialIssuerConfig(
                new URI("http://example.com/token"),
                new URI("http://example.com/credential"),
                new URI("http://example.com/authorize"),
                "ipv-core",
                "test-jwk",
                "test-jwk",
                criIss,
                new URI("http://www.example.com/credential-issuers/callback/criId"));
    }
}
