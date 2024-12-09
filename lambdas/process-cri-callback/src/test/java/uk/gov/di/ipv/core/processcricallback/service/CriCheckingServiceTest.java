package uk.gov.di.ipv.core.processcricallback.service;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcricallback.exception.InvalidCriCallbackRequestException;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.DL_AUTH_SOURCE_CHECK;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_TARGET_VOT;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.DCMAW_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitEmptyDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermitNonDcmaw;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ACCESS_DENIED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DL_AUTH_SOURCE_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_INVALID_REQUEST_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_TEMPORARILY_UNAVAILABLE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_VCS_NOT_CORRELATED;

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
    private static final List<ContraIndicator> TEST_CONTRA_INDICATORS = List.of();

    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private CimitService mockCimitService;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private MockedStatic<VcHelper> mockedVcHelper;
    @Mock private IpvSessionService mockIpvSessionService;
    @InjectMocks private CriCheckingService criCheckingService;

    @Test
    void handleCallbackErrorShouldReturnJourneyErrorByDefault() {
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
    void handleCallbackErrorShouldReturnJourneyAccessDeniedIfInCallbackRequest() {
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
    void handleCallbackErrorShouldReturnJourneyInvalidRequestIfInCallbackRequest() {
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
    void handleCallbackErrorShouldReturnJourneyTemporarilyAvailableIfInCallbackRequest() {
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
    void handleCallbackErrorShouldReturnSendCorrectAuditEvent() {
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
        callbackRequest.setIpvSessionId("");

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
        callbackRequest.setIpvSessionId("");
        callbackRequest.setState("");

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
        callbackRequest.setIpvSessionId("");

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
        callbackRequest.setState("");

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
        callbackRequest.setAuthorizationCode("");

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
        callbackRequest.setIpvSessionId("");

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
        callbackRequest.setState("");

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
        var sessionVcs = List.of(M1B_DCMAW_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var ipvSessionItem = buildValidIpvSessionItem();
        when(mockCimitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.empty());
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);
        mockedVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        vcs,
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        sessionVcs);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), result);
    }

    @Test
    void checkVcResponseShouldReturnNextWhenAllChecksPassForLowerConfidenceVot() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var vcs = List.of(M1A_ADDRESS_VC);
        var sessionVcs = List.of(M1B_DCMAW_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var ipvSessionItem = buildValidIpvSessionItem();
        ipvSessionItem.setTargetVot(Vot.P1);
        when(mockCimitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), eq(Vot.P1)))
                .thenReturn(Optional.empty());
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);
        mockedVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        vcs,
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        sessionVcs);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), result);
    }

    @Test
    void checkVcResponseShouldThrowIfTargetVotIsNull() {
        // Arrange
        var ipvSessionItem = buildValidIpvSessionItem();
        ipvSessionItem.setTargetVot(null);

        // Act
        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                criCheckingService.checkVcResponse(
                                        List.of(),
                                        "1.1.1.1",
                                        buildValidClientOAuthSessionItem(),
                                        ipvSessionItem,
                                        List.of(M1B_DCMAW_VC)));

        // Assert
        assertEquals(MISSING_TARGET_VOT, exception.getErrorResponse());
    }

    @Test
    void checkVcResponseShouldReturnFailWithCiWhenUserBreachesCiThreshold() throws Exception {
        // Arrange for CI threshold breach
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var ipvSessionItem = buildValidIpvSessionItem();
        when(mockCimitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.of(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH)));

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(),
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        List.of());

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH), result);
    }

    @Test
    void checkVcResponseDoesNotCheckForCIsWhenOnReverificationJourney() throws Exception {
        // Arrange and set scope to reverification
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var ipvSessionItem = buildValidIpvSessionItem();
        clientOAuthSessionItem.setScope(ScopeConstants.REVERIFICATION);
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(false);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(),
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        List.of());

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_VCS_NOT_CORRELATED), result);
        verify(mockCimitService, never()).getContraIndicators(any(), any(), any());
        verify(mockCimitUtilityService, never()).getMitigationJourneyIfBreaching(any(), any());
        verify(mockIpvSessionService, times(1)).updateIpvSession(ipvSessionItem);
    }

    @Test
    void checkVcResponseShouldReturnMitigatedJourneyWhenCiMitigationIsPossible() throws Exception {
        // Arrange for CI mitigation possibility
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var ipvSessionItem = buildValidIpvSessionItem();
        when(mockCimitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.of(new JourneyResponse("/journey/mitigation-journey")));

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(),
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        List.of());

        // Assert
        assertEquals(new JourneyResponse("/journey/mitigation-journey"), result);
    }

    @Test
    void checkVcResponseShouldReturnVcsNotCorrelatedWhenVcsNotCorrelated() throws Exception {
        // Arrange for VCs not correlated
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var ipvSessionItem = buildValidIpvSessionItem();
        when(mockCimitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.empty());
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(false);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        List.of(),
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        List.of());

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_VCS_NOT_CORRELATED), result);
    }

    @Test
    void checkVcResponseShouldReturnFailWithNoCiWhenVcsNotSuccessful() throws Exception {
        // Arrange for VCs not successful
        var callbackRequest = buildValidCallbackRequest();
        var vcs = List.of(M1A_ADDRESS_VC);
        var sessionVcs = List.of(M1B_DCMAW_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var ipvSessionItem = buildValidIpvSessionItem();
        when(mockCimitService.getContraIndicators(any(), any(), any()))
                .thenReturn(TEST_CONTRA_INDICATORS);
        when(mockCimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                .thenReturn(Optional.empty());
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);
        mockedVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(false);

        // Act
        JourneyResponse result =
                criCheckingService.checkVcResponse(
                        vcs,
                        callbackRequest.getIpAddress(),
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        sessionVcs);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_PATH), result);
    }

    @Nested
    class DrivingLicenceAuthSourceCheck {

        @BeforeEach
        void setup() throws Exception {
            when(mockConfigService.enabled(DL_AUTH_SOURCE_CHECK)).thenReturn(true);
            when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);
            mockedVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true);
        }

        @Test
        void checkVcResponseShouldReturnDlAuthSourceCheckForDlDcmawVcAndNoDrivingLicenceVc()
                throws Exception {
            var callbackRequest = buildValidCallbackRequest();
            var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
            var ipvSessionItem = buildValidIpvSessionItem();

            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            List.of(M1B_DCMAW_VC),
                            callbackRequest.getIpAddress(),
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of());

            assertEquals(new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_PATH), result);
        }

        @Test
        void checkVcResponseShouldReturnDlAuthSourceCheckForDlDcmawVcAndFailedDrivingLicenceVc()
                throws Exception {
            var callbackRequest = buildValidCallbackRequest();
            var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
            var ipvSessionItem = buildValidIpvSessionItem();

            var drivingPermitVc = vcDrivingPermit();

            mockedVcHelper.when(() -> VcHelper.isSuccessfulVc(M1B_DCMAW_VC)).thenCallRealMethod();
            mockedVcHelper.when(() -> VcHelper.isSuccessfulVc(drivingPermitVc)).thenReturn(false);

            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            List.of(M1B_DCMAW_VC),
                            callbackRequest.getIpAddress(),
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of(M1B_DCMAW_VC));

            assertEquals(new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_PATH), result);
        }

        @Test
        void checkVcResponseShouldReturnDlAuthSourceCheckForDlDcmawVcAndDlVcWithMissingPermit()
                throws Exception {
            var callbackRequest = buildValidCallbackRequest();
            var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
            var ipvSessionItem = buildValidIpvSessionItem();

            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            List.of(M1B_DCMAW_VC),
                            callbackRequest.getIpAddress(),
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of(M1B_DCMAW_VC));

            assertEquals(new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_PATH), result);
        }

        @Test
        void checkVcResponseShouldReturnDlAuthSourceCheckForDlDcmawVcAndDlVcEmptyDrivingPermit()
                throws Exception {
            var callbackRequest = buildValidCallbackRequest();
            var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
            var ipvSessionItem = buildValidIpvSessionItem();

            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            List.of(M1B_DCMAW_VC),
                            callbackRequest.getIpAddress(),
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of(vcDrivingPermitEmptyDrivingPermit()));

            assertEquals(new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_PATH), result);
        }

        @Test
        void checkVcResponseShouldReturnDlAuthSourceIfDrivingPermitIdentifiersDiffer()
                throws Exception {
            var callbackRequest = buildValidCallbackRequest();
            var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
            var ipvSessionItem = buildValidIpvSessionItem();

            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            List.of(M1B_DCMAW_VC),
                            callbackRequest.getIpAddress(),
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of(vcDrivingPermitNonDcmaw()));

            assertEquals(new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_PATH), result);
        }

        @Test
        void
                checkVcResponseShouldNotReturnDlAuthSourceCheckForDlDcmawVcAndDrivingLicenceVcIfIdentifiersMatch()
                        throws Exception {
            var callbackRequest = buildValidCallbackRequest();
            var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
            var ipvSessionItem = buildValidIpvSessionItem();

            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            List.of(M1B_DCMAW_VC),
                            callbackRequest.getIpAddress(),
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of(vcDrivingPermit()));

            assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), result);
        }

        @Test
        void checkVcResponseShouldNotReturnDlAuthSourceCheckForNonDlDcmawVc() throws Exception {
            var callbackRequest = buildValidCallbackRequest();
            var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
            var ipvSessionItem = buildValidIpvSessionItem();

            JourneyResponse result =
                    criCheckingService.checkVcResponse(
                            List.of(DCMAW_PASSPORT_VC),
                            callbackRequest.getIpAddress(),
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of());

            assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), result);
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
        ipvSessionItem.setTargetVot(Vot.P2);
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.setCriOAuthSessionId(TEST_CRI_OAUTH_SESSION_ID);
        return ipvSessionItem;
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .userId(TEST_USER_ID)
                .scope(ScopeConstants.OPENID)
                .vtr(List.of("P2"))
                .build();
    }
}
