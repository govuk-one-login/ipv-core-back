package uk.gov.di.ipv.core.processcricallback.service;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcricallback.exception.InvalidCriCallbackRequestException;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ACCESS_DENIED_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_INVALID_REQUEST_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_TEMPORARILY_UNAVAILABLE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_VCS_NOT_CORRELATED;

@ExtendWith(MockitoExtension.class)
class CriCheckingServiceTest {
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_ERROR = "test_error";
    private static final String TEST_ERROR_DESCRIPTION = "test_error_description";
    private static final String TEST_COMPONENT_ID = "component_id";
    private static final String TEST_IPV_SESSION_ID = "test_ipv_Session_id";
    private static final String TEST_CRI_OAUTH_SESSION_ID = "test_cri_oauth_session_id";
    private static final String TEST_USER_ID = "test_user_id";
    private static final String TEST_GOVUK_SIGNIN_JOURNEY_ID = "test_govuk_signin_journey_id";
    private static final String TEST_CI_CODE = "test_ci_code";
    private static final ContraIndicators TEST_CONTRA_INDICATORS =
            ContraIndicators.builder()
                    .usersContraIndicators(
                            List.of(
                                    ContraIndicator.builder()
                                            .code(TEST_CI_CODE)
                                            .mitigation(List.of(Mitigation.builder().build()))
                                            .build()))
                    .build();

    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private CiMitService mockCiMitService;
    @Mock private CiMitUtilityService mockCimitUtilityService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @InjectMocks private CriCheckingService criCheckingService;

    @Test
    void handleCallbackErrorShouldReturnJourneyErrorByDefault() throws SqsException {
        // Arrange
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(F2F.getId())
                        .error(TEST_ERROR)
                        .errorDescription(TEST_ERROR_DESCRIPTION)
                        .build();
        var clientOauthSessionItem = ClientOAuthSessionItem.builder().build();
        when(mockConfigService.getParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(TEST_COMPONENT_ID);

        // Act
        var journeyResponse =
                criCheckingService.handleCallbackError(callbackRequest, clientOauthSessionItem);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_ERROR_PATH), journeyResponse);
    }

    @Test
    void handleCallbackErrorShouldReturnJourneyAccessDeniedIfInCallbackRequest()
            throws SqsException {
        // Arrange
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(F2F.getId())
                        .error(OAuth2Error.ACCESS_DENIED_CODE)
                        .errorDescription(TEST_ERROR_DESCRIPTION)
                        .build();
        var clientOauthSessionItem = ClientOAuthSessionItem.builder().build();
        when(mockConfigService.getParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(TEST_COMPONENT_ID);

        // Act
        var journeyResponse =
                criCheckingService.handleCallbackError(callbackRequest, clientOauthSessionItem);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_ACCESS_DENIED_PATH), journeyResponse);
    }

    @Test
    void handleCallbackErrorShouldReturnJourneyInvalidRequestIfInCallbackRequest()
            throws SqsException {
        // Arrange
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(F2F.getId())
                        .error(OAuth2Error.INVALID_REQUEST_CODE)
                        .errorDescription(TEST_ERROR_DESCRIPTION)
                        .build();
        var clientOauthSessionItem = ClientOAuthSessionItem.builder().build();
        when(mockConfigService.getParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(TEST_COMPONENT_ID);

        // Act
        var journeyResponse =
                criCheckingService.handleCallbackError(callbackRequest, clientOauthSessionItem);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_INVALID_REQUEST_PATH), journeyResponse);
    }

    @Test
    void handleCallbackErrorShouldReturnJourneyTemporarilyAvailableIfInCallbackRequest()
            throws SqsException {
        // Arrange
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(F2F.getId())
                        .error(OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE)
                        .errorDescription(TEST_ERROR_DESCRIPTION)
                        .build();
        var clientOauthSessionItem = ClientOAuthSessionItem.builder().build();
        when(mockConfigService.getParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(TEST_COMPONENT_ID);

        // Act
        var journeyResponse =
                criCheckingService.handleCallbackError(callbackRequest, clientOauthSessionItem);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_TEMPORARILY_UNAVAILABLE_PATH), journeyResponse);
    }

    @Test
    void handleCallbackErrorShouldReturnSendCorrectAuditEvent() throws SqsException {
        // Arrange
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(F2F.getId())
                        .error(TEST_ERROR)
                        .errorDescription(TEST_ERROR_DESCRIPTION)
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .build();
        var clientOauthSessionItem =
                ClientOAuthSessionItem.builder()
                        .userId(TEST_USER_ID)
                        .govukSigninJourneyId(TEST_GOVUK_SIGNIN_JOURNEY_ID)
                        .build();
        when(mockConfigService.getParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(TEST_COMPONENT_ID);
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // Act
        criCheckingService.handleCallbackError(callbackRequest, clientOauthSessionItem);

        // Assert
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();
        assertEquals(
                AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, capturedAuditEvent.getEventName());
        assertEquals(TEST_COMPONENT_ID, capturedAuditEvent.getComponentId());
        assertEquals(TEST_USER_ID, capturedAuditEvent.getUser().getUserId());
        assertEquals(TEST_IPV_SESSION_ID, capturedAuditEvent.getUser().getSessionId());
        assertEquals(
                TEST_GOVUK_SIGNIN_JOURNEY_ID,
                capturedAuditEvent.getUser().getGovukSigninJourneyId());
        assertEquals(
                TEST_ERROR,
                ((AuditExtensionErrorParams) capturedAuditEvent.getExtensions()).getErrorCode());
        assertEquals(
                TEST_ERROR_DESCRIPTION,
                ((AuditExtensionErrorParams) capturedAuditEvent.getExtensions())
                        .getErrorDescription());
    }

    @Test
    void validateSessionIdsShouldNotThrowExceptionWhenSessionIdsAreValid() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();

        // Act & Assert
        assertDoesNotThrow(() -> criCheckingService.validateSessionIds(callbackRequest));
    }

    @Test
    void validateSessionIdsShouldThrowExceptionWhenIpvSessionIdIsBlank() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setIpvSessionId(StringUtils.EMPTY);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () -> criCheckingService.validateSessionIds(callbackRequest),
                "Expected validateSessionIds to throw, but it didn't");
    }

    @Test
    void validateSessionIdsShouldThrowExceptionWhenBothSessionIdsAreBlank() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setIpvSessionId(StringUtils.EMPTY);
        callbackRequest.setState(StringUtils.EMPTY);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () -> criCheckingService.validateSessionIds(callbackRequest),
                "Expected validateSessionIds to throw, but it didn't");
    }

    @Test
    void validateSessionIdsShouldThrowExceptionWithNoIpvForCriOauthSessionError() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setIpvSessionId(StringUtils.EMPTY);

        // Act & Assert
        var exception =
                assertThrows(
                        InvalidCriCallbackRequestException.class,
                        () -> criCheckingService.validateSessionIds(callbackRequest));
        assertEquals(ErrorResponse.NO_IPV_FOR_CRI_OAUTH_SESSION, exception.getErrorResponse());
    }

    @Test
    void validateSessionIdsShouldNotThrowExceptionWithMissingOauthStateErrorWhenOnlyStateIsBlank() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setState(StringUtils.EMPTY);

        // Act & Assert
        assertDoesNotThrow(() -> criCheckingService.validateSessionIds(callbackRequest));
    }

    @Test
    void validateCallbackRequestShouldNotThrowExceptionWhenValid() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem(callbackRequest.getState());

        // Act & Assert
        assertDoesNotThrow(
                () ->
                        criCheckingService.validateCallbackRequest(
                                callbackRequest, criOAuthSessionItem));
    }

    @Test
    void validateCallbackRequestShouldThrowExceptionWhenAuthorizationCodeIsBlank() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setAuthorizationCode(StringUtils.EMPTY);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateCallbackRequest(
                                callbackRequest,
                                buildValidCriOAuthSessionItem(callbackRequest.getState())),
                ErrorResponse.MISSING_AUTHORIZATION_CODE.toString());
    }

    @Test
    void validateCallbackRequestShouldThrowExceptionWhenCredentialIssuerIdIsBlank() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setCredentialIssuerId(null);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateCallbackRequest(
                                callbackRequest,
                                buildValidCriOAuthSessionItem(callbackRequest.getState())),
                ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.toString());
    }

    @Test
    void validateCallbackRequestShouldThrowExceptionWhenIpvSessionIdIsBlank() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setIpvSessionId(StringUtils.EMPTY);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateCallbackRequest(
                                callbackRequest,
                                buildValidCriOAuthSessionItem(callbackRequest.getState())),
                ErrorResponse.MISSING_IPV_SESSION_ID.toString());
    }

    @Test
    void validateCallbackRequestShouldThrowExceptionWhenStateIsBlank() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setState(StringUtils.EMPTY);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateCallbackRequest(
                                callbackRequest,
                                buildValidCriOAuthSessionItem(callbackRequest.getState())),
                ErrorResponse.MISSING_OAUTH_STATE.toString());
    }

    @Test
    void validateCallbackRequestShouldThrowExceptionWhenStateDoesNotMatchPersistedState() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem("differentState");

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateCallbackRequest(
                                callbackRequest, criOAuthSessionItem),
                ErrorResponse.INVALID_OAUTH_STATE.toString());
    }

    @Test
    void validateCallbackRequestShouldThrowExceptionWhenCredentialIssuerIdIsInvalid() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setCredentialIssuerId("invalid");
        var criOAuthSessionItem = buildValidCriOAuthSessionItem(callbackRequest.getState());

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateCallbackRequest(
                                callbackRequest, criOAuthSessionItem),
                ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID.toString());
    }

    @Test
    void validateOAuthForErrorShouldThrowWhenCriOAuthSessionItemIsNull() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var ipvSessionItem = buildValidIpvSessionItem();

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateOAuthForError(
                                callbackRequest, null, ipvSessionItem),
                ErrorResponse.INVALID_OAUTH_STATE.toString());
    }

    @Test
    void validateOAuthForErrorShouldThrowWhenCriIdDoesNotMatch() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem(callbackRequest.getState());
        var ipvSessionItem = buildValidIpvSessionItem();
        criOAuthSessionItem.setCriId("differentCriId");

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () ->
                        criCheckingService.validateOAuthForError(
                                callbackRequest, criOAuthSessionItem, ipvSessionItem),
                ErrorResponse.INVALID_OAUTH_STATE.toString());
    }

    @Test
    void validateOAuthForErrorShouldNotThrowWhenDataIsValid() {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem(callbackRequest.getState());
        var ipvSessionItem = buildValidIpvSessionItem();

        // Act & Assert
        assertDoesNotThrow(
                () ->
                        criCheckingService.validateOAuthForError(
                                callbackRequest, criOAuthSessionItem, ipvSessionItem));
    }

    @Test
    void validatePendingVcResponseShouldNotThrowExceptionWhenUserIdsMatch() {
        // Arrange
        var vcResponse = VerifiableCredentialResponse.builder().userId(TEST_USER_ID).build();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act & Assert
        assertDoesNotThrow(
                () ->
                        criCheckingService.validatePendingVcResponse(
                                vcResponse, clientOAuthSessionItem));
    }

    @Test
    void validatePendingVcResponseShouldThrowExceptionWhenUserIdsDoNotMatch() {
        // Arrange
        var vcResponse = VerifiableCredentialResponse.builder().userId("wrongUserId").build();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act & Assert
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () ->
                                criCheckingService.validatePendingVcResponse(
                                        vcResponse, clientOAuthSessionItem));

        // Assert
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE,
                exception.getErrorResponse());
    }

    @Test
    void checkVcResponseShouldReturnNextWhenAllChecksPass() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var vcs = List.of(M1A_ADDRESS_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        when(mockCiMitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.isBreachingCiThreshold(any())).thenReturn(false);
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);
        try (MockedStatic<VcHelper> mockedVcHelper = Mockito.mockStatic(VcHelper.class)) {
            mockedVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true);

            // Act
            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            vcs, callbackRequest, clientOAuthSessionItem, TEST_IPV_SESSION_ID);

            // Assert
            assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), result);
            verify(mockSessionCredentialsService).getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID);
        }
    }

    @Test
    void checkVcResponseShouldReturnFailWithCiWhenUserBreachesCiThreshold() throws Exception {
        // Arrange for CI threshold breach
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        when(mockCiMitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(), callbackRequest, clientOAuthSessionItem, TEST_IPV_SESSION_ID);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH), result);
    }

    @Test
    void checkVcResponseDoesNotCheckForCIsWhenOnReverificationJourney() throws Exception {
        // Arrange and set scope to reverification
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        clientOAuthSessionItem.setScope(ScopeConstants.REVERIFICATION);
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(false);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(), callbackRequest, clientOAuthSessionItem, TEST_IPV_SESSION_ID);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_VCS_NOT_CORRELATED), result);
        verify(mockCiMitService, never()).getContraIndicators(any(), any(), any());
        verify(mockCimitUtilityService, never()).isBreachingCiThreshold(any());
    }

    @Test
    void checkVcResponseShouldReturnMitigatedJourneyWhenCiMitigationIsPossible() throws Exception {
        // Arrange for CI mitigation possibility
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        when(mockCiMitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(mockCimitUtilityService.getCiMitigationJourneyResponse(any()))
                .thenReturn(Optional.of(new JourneyResponse("/journey/mitigation-journey")));

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(), callbackRequest, clientOAuthSessionItem, TEST_IPV_SESSION_ID);

        // Assert
        assertEquals(new JourneyResponse("/journey/mitigation-journey"), result);
    }

    @Test
    void checkVcResponseShouldReturnVcsNotCorrelatedWhenVcsNotCorrelated() throws Exception {
        // Arrange for VCs not correlated
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        when(mockCiMitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.isBreachingCiThreshold(any())).thenReturn(false);
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(false);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(), callbackRequest, clientOAuthSessionItem, TEST_IPV_SESSION_ID);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_VCS_NOT_CORRELATED), result);
        verify(mockSessionCredentialsService).getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID);
    }

    @Test
    void checkVcResponseShouldReturnFailWithNoCiWhenVcsNotSuccessful() throws Exception {
        // Arrange for VCs not successful
        var callbackRequest = buildValidCallbackRequest();
        var vcs = List.of(M1A_ADDRESS_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        when(mockCiMitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.isBreachingCiThreshold(any())).thenReturn(false);
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);
        try (MockedStatic<VcHelper> mockedJwtHelper = Mockito.mockStatic(VcHelper.class)) {
            mockedJwtHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(false);

            // Act
            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            vcs, callbackRequest, clientOAuthSessionItem, TEST_IPV_SESSION_ID);

            // Assert
            assertEquals(new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_PATH), result);
            verify(mockSessionCredentialsService).getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID);
        }
    }

    private CriCallbackRequest buildValidCallbackRequest() {
        return CriCallbackRequest.builder()
                .ipvSessionId(TEST_IPV_SESSION_ID)
                .credentialIssuerId(F2F.getId())
                .authorizationCode(TEST_AUTHORISATION_CODE)
                .state(TEST_CRI_OAUTH_SESSION_ID)
                .build();
    }

    private CriOAuthSessionItem buildValidCriOAuthSessionItem(String state) {
        return CriOAuthSessionItem.builder().criId(F2F.getId()).criOAuthSessionId(state).build();
    }

    private IpvSessionItem buildValidIpvSessionItem() {
        var ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setCriOAuthSessionId(TEST_CRI_OAUTH_SESSION_ID);
        return ipvSessionItem;
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .userId(TEST_USER_ID)
                .scope(ScopeConstants.OPENID)
                .build();
    }
}
