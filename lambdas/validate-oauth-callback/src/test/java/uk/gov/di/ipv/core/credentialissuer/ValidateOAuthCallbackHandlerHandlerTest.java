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
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
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
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DRIVING_LICENCE_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;

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
    private static final String CRI_PASSPORT = "ukPassport";
    private static final String CRI_DRIVING_LICENCE = "drivingLicence";
    private static CredentialIssuerConfig credentialIssuerConfig;
    private static IpvSessionItem ipvSessionItem;
    @Mock private Context context;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private AuditService mockAuditService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;
    private ValidateOAuthCallbackHandler underTest;
    private CriOAuthSessionItem criOAuthSessionItem;

    @BeforeEach
    void setUpBeforeEach() throws URISyntaxException {
        when(mockConfigService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn("audience.for.clients");
        when(mockConfigService.getSsmParameter(PASSPORT_CRI_ID)).thenReturn(CRI_PASSPORT);
        when(mockConfigService.getSsmParameter(DRIVING_LICENCE_CRI_ID))
                .thenReturn(CRI_DRIVING_LICENCE);

        credentialIssuerConfig = createCriConfig("criId", "cri.iss.com", true);

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

        criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId("testState")
                        .criId("testCRI")
                        .accessToken("testAccessToken")
                        .authorizationCode(TEST_AUTHORIZATION_CODE)
                        .journeyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY)
                        .build();

        underTest =
                new ValidateOAuthCallbackHandler(
                        mockConfigService,
                        mockIpvSessionService,
                        mockAuditService,
                        mockCriOAuthSessionService);
    }

    @Test
    void shouldPersistAuthorizationCodeInIPVSessionTable() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(any()))
                .thenReturn(criOAuthSessionItem);

        Map<String, Object> output = underTest.handleRequest(validCriCallbackRequest(), context);

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

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutAuthCode, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_AUTHORIZATION_CODE.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() {
        CriCallbackRequest criCallbackRequestWithoutCriId = validCriCallbackRequest();
        criCallbackRequestWithoutCriId.setCredentialIssuerId(null);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutCriId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet() {
        CriCallbackRequest criCallbackRequestWithInvalidCriId = validCriCallbackRequest();
        criCallbackRequestWithInvalidCriId.setCredentialIssuerId("an invalid id");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithInvalidCriId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfSessionIdNotPresent() {
        CriCallbackRequest criCallbackRequestWithoutSessionId = validCriCallbackRequest();
        criCallbackRequestWithoutSessionId.setIpvSessionId(null);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutSessionId, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfOAuthStateNotPresentInRequest() {
        CriCallbackRequest criCallbackRequestWithoutState = validCriCallbackRequest();
        criCallbackRequestWithoutState.setState(null);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithoutState, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_OAUTH_STATE.getMessage(), output.get(MESSAGE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseWithAttemptRecoveryPageIfOAuthStateNotPresentInSession() {
        CriCallbackRequest criCallbackRequest = validCriCallbackRequest();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setCredentialIssuerSessionDetails(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output = underTest.handleRequest(criCallbackRequest, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals("pyi-attempt-recovery", output.get(PAGE));
        assertEquals("error", output.get(TYPE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceive400ResponseWithAttemptRecoveryPageIfOAuthStateNotValid() {
        CriCallbackRequest criCallbackRequestWithInvalidState = validCriCallbackRequest();
        criCallbackRequestWithInvalidState.setState("not-correct-state");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithInvalidState, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals("pyi-attempt-recovery", output.get(PAGE));
        assertEquals("error", output.get(TYPE));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldUpdateSessionWithDetailsOfFailedVisitedCriOnSqsException() throws Exception {
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(credentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

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
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceiveAccessDeniedJourneyResponseWhenOauthErrorAccessDeniedAndOnlyPassportEnabled()
            throws URISyntaxException {
        CriCallbackRequest criCallbackRequestWithAccessDenied = validCriCallbackRequest();
        criCallbackRequestWithAccessDenied.setError(TEST_OAUTH_ACCESS_DENIED_ERROR);
        criCallbackRequestWithAccessDenied.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigService.isEnabled(CRI_PASSPORT)).thenReturn(true);

        when(mockConfigService.isEnabled(CRI_DRIVING_LICENCE)).thenReturn(false);
        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithAccessDenied, context);

        assertEquals("/journey/access-denied", output.get("journey"));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void
            shouldReceiveAccessDeniedMultiJourneyResponseWhenOauthErrorAccessDeniedAndBothPassportAndDrivingLicenceEnabled()
                    throws URISyntaxException {
        CriCallbackRequest criCallbackRequestWithAccessDenied = validCriCallbackRequest();
        criCallbackRequestWithAccessDenied.setError(TEST_OAUTH_ACCESS_DENIED_ERROR);
        criCallbackRequestWithAccessDenied.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        when(mockConfigService.isEnabled(CRI_PASSPORT)).thenReturn(true);

        when(mockConfigService.isEnabled(CRI_DRIVING_LICENCE)).thenReturn(true);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithAccessDenied, context);

        assertEquals("/journey/access-denied-multi-doc", output.get("journey"));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceiveTemporarilyUnavailableJourneyResponseWhenOauthErrorTemporarilyUnavailable() {
        CriCallbackRequest criCallbackRequestWithAccessDenied = validCriCallbackRequest();
        criCallbackRequestWithAccessDenied.setError(OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE);
        criCallbackRequestWithAccessDenied.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithAccessDenied, context);

        assertEquals("/journey/temporarily-unavailable", output.get("journey"));
        verify(mockCriOAuthSessionService, times(0)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReceiveJourneyErrorJourneyResponseWhenAnyOtherOauthError() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithOtherError, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    @Test
    void shouldAttemptRecoveryErrorResponseWhenOauthSessionIsNull() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        ipvSessionItem.setCredentialIssuerSessionDetails(null);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

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

        CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto =
                new CredentialIssuerSessionDetailsDto();
        credentialIssuerSessionDetailsDto.setCriId("test");
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        Map<String, Object> output =
                underTest.handleRequest(criCallbackRequestWithOtherError, context);

        assertEquals("error", output.get("type"));
        assertEquals("pyi-attempt-recovery", output.get("page"));
        assertEquals(400, output.get("statusCode"));
    }

    @Test
    void shouldNotUpdateSessionOnAttemptRecoveryError() {
        CriCallbackRequest criCallbackRequestWithOtherError = validCriCallbackRequest();
        criCallbackRequestWithOtherError.setError(TEST_OAUTH_SERVER_ERROR);
        criCallbackRequestWithOtherError.setErrorDescription(TEST_ERROR_DESCRIPTION);

        CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto =
                new CredentialIssuerSessionDetailsDto();
        credentialIssuerSessionDetailsDto.setCriId("test");
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

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

    private CredentialIssuerConfig createCriConfig(String criId, String criIss, boolean enabled)
            throws URISyntaxException {
        return new CredentialIssuerConfig(
                criId,
                criId,
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
