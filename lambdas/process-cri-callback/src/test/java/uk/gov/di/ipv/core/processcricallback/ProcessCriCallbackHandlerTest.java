package uk.gov.di.ipv.core.processcricallback;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.MitigationRouteConfigNotFoundException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;
import uk.gov.di.ipv.core.processcricallback.exception.InvalidCriCallbackRequestException;
import uk.gov.di.ipv.core.processcricallback.service.CriApiService;
import uk.gov.di.ipv.core.processcricallback.service.CriCheckingService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
class ProcessCriCallbackHandlerTest {
    private static final String TEST_CRI_ID = "test_cri_id";
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_ERROR = "test_error";
    private static final String TEST_IPV_SESSION_ID = "test_ipv_Session_id";
    private static final String TEST_CRI_OAUTH_SESSION_ID = "test_cri_oauth_session_id";
    private static final String TEST_USER_ID = "test_user_id";
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;
    @Mock private VerifiableCredentialValidator mockVerifiableCredentialValidator;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private CriApiService mockCriApiService;
    @Mock private CriStoringService mockCriStoringService;
    @Mock private CriCheckingService mockCriCheckingService;
    @InjectMocks private ProcessCriCallbackHandler processCriCallbackHandler;

    @BeforeEach
    void setUp() {
        processCriCallbackHandler =
                new ProcessCriCallbackHandler(
                        mockConfigService,
                        mockIpvSessionService,
                        mockCriOAuthSessionService,
                        mockVerifiableCredentialValidator,
                        mockClientOAuthSessionDetailsService,
                        mockCriApiService,
                        mockCriStoringService,
                        mockCriCheckingService);
    }

    @Test
    void getJourneyResponseShouldReturnNextWhenAllChecksPassForCreatedVcs() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .verifiableCredentials(
                                List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString()))
                        .credentialStatus(VerifiableCredentialStatus.CREATED)
                        .build();
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        when(mockCriApiService.fetchVerifiableCredential(
                        bearerToken, callbackRequest, criOAuthSessionItem))
                .thenReturn(vcResponse);
        when(mockVerifiableCredentialValidator.parseAndValidate(
                        any(), any(), any(), any(), any(), any()))
                .thenReturn(vcs);
        when(mockCriCheckingService.checkVcResponse(
                        any(), eq(callbackRequest), eq(clientOAuthSessionItem)))
                .thenReturn(new JourneyResponse(JOURNEY_NEXT_PATH));
        when(mockConfigService.getOauthCriConfig(any()))
                .thenReturn(
                        OauthCriConfig.builder().signingKey(TestFixtures.EC_PUBLIC_JWK).build());

        // Act
        var result = processCriCallbackHandler.getJourneyResponse(callbackRequest);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), result);
        verify(mockCriCheckingService).validateSessionIds(callbackRequest);
        verify(mockCriCheckingService)
                .validateCallbackRequest(callbackRequest, criOAuthSessionItem);
        verify(mockCriStoringService)
                .storeVcs(
                        callbackRequest.getCredentialIssuerId(),
                        callbackRequest.getIpAddress(),
                        vcs,
                        clientOAuthSessionItem,
                        ipvSessionItem);
    }

    @Test
    void getJourneyResponseShouldReturnNextWhenAllChecksPassForPendingVcs() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .credentialStatus(VerifiableCredentialStatus.PENDING)
                        .build();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        when(mockCriApiService.fetchVerifiableCredential(
                        bearerToken, callbackRequest, criOAuthSessionItem))
                .thenReturn(vcResponse);
        when(mockCriCheckingService.checkVcResponse(
                        List.of(), callbackRequest, clientOAuthSessionItem))
                .thenReturn(new JourneyResponse(JOURNEY_NEXT_PATH));

        // Act
        var result = processCriCallbackHandler.getJourneyResponse(callbackRequest);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), result);
        verify(mockCriCheckingService).validateSessionIds(callbackRequest);
        verify(mockCriStoringService).storeCriResponse(callbackRequest, clientOAuthSessionItem);
    }

    @Test
    void getJourneyResponseShouldThrowWhenValidateSessionIdsFails()
            throws InvalidCriCallbackRequestException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        doThrow(new InvalidCriCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE))
                .when(mockCriCheckingService)
                .validateSessionIds(callbackRequest);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () -> processCriCallbackHandler.getJourneyResponse(callbackRequest));
    }

    @Test
    void getJourneyResponseShouldThrowWhenCriStoringServiceThrows() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .verifiableCredentials(
                                List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString()))
                        .credentialStatus(VerifiableCredentialStatus.CREATED)
                        .build();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        when(mockCriApiService.fetchVerifiableCredential(
                        bearerToken, callbackRequest, criOAuthSessionItem))
                .thenReturn(vcResponse);
        when(mockConfigService.getOauthCriConfig(any()))
                .thenReturn(
                        OauthCriConfig.builder().signingKey(TestFixtures.EC_PUBLIC_JWK).build());
        when(mockCriCheckingService.checkVcResponse(
                        any(), eq(callbackRequest), eq(clientOAuthSessionItem)))
                .thenThrow(
                        new MitigationRouteConfigNotFoundException(
                                "mitigation route event not found"));
        // Assert
        assertThrows(
                MitigationRouteConfigNotFoundException.class,
                () -> processCriCallbackHandler.getJourneyResponse(callbackRequest));
    }

    @Test
    void getJourneyResponseShouldThrowWhenAccessTokenCannotBeFetched() throws CriApiException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        doThrow(
                        new CriApiException(
                                HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST))
                .when(mockCriApiService)
                .fetchAccessToken(eq(callbackRequest), any(CriOAuthSessionItem.class));

        // Act & Assert
        assertThrows(
                CriApiException.class,
                () -> processCriCallbackHandler.getJourneyResponse(callbackRequest));
    }

    @Test
    void getJourneyResponseShouldThrowWhenVerifiableCredentialCannotBeFetched()
            throws CriApiException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();
        var bearerToken = new BearerAccessToken("value");

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem))
                .thenReturn(bearerToken);
        doThrow(
                        new CriApiException(
                                HTTPResponse.SC_BAD_REQUEST,
                                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE))
                .when(mockCriApiService)
                .fetchVerifiableCredential(
                        any(BearerAccessToken.class),
                        eq(callbackRequest),
                        any(CriOAuthSessionItem.class));

        // Act & Assert
        assertThrows(
                CriApiException.class,
                () -> processCriCallbackHandler.getJourneyResponse(callbackRequest));
    }

    @Test
    void getJourneyResponseShouldHandleErrorResponseFromCri() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        callbackRequest.setError(TEST_ERROR);
        var ipvSessionItem = buildValidIpvSessionItem();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var criOAuthSessionItem = buildValidCriOAuthSessionItem();

        when(mockIpvSessionService.getIpvSession(callbackRequest.getIpvSessionId()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCriOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId()))
                .thenReturn(criOAuthSessionItem);
        when(mockCriCheckingService.handleCallbackError(
                        eq(callbackRequest), any(ClientOAuthSessionItem.class)))
                .thenReturn(new JourneyResponse(JOURNEY_ERROR_PATH));

        // Act
        var result = processCriCallbackHandler.getJourneyResponse(callbackRequest);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_ERROR_PATH), result);
        verify(mockCriCheckingService).validateOAuthForError(eq(callbackRequest), any(), any());
    }

    @Test
    void getJourneyResponseShouldHandleNoIpvForCriOAuthSessionException()
            throws InvalidCriCallbackRequestException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        doThrow(new InvalidCriCallbackRequestException(ErrorResponse.NO_IPV_FOR_CRI_OAUTH_SESSION))
                .when(mockCriCheckingService)
                .validateSessionIds(callbackRequest);

        // Act & Assert
        assertThrows(
                InvalidCriCallbackRequestException.class,
                () -> processCriCallbackHandler.getJourneyResponse(callbackRequest));
    }

    private CriCallbackRequest buildValidCallbackRequest() {
        return CriCallbackRequest.builder()
                .ipvSessionId(TEST_IPV_SESSION_ID)
                .credentialIssuerId(TEST_CRI_ID)
                .authorizationCode(TEST_AUTHORISATION_CODE)
                .state(TEST_CRI_OAUTH_SESSION_ID)
                .build();
    }

    private CriOAuthSessionItem buildValidCriOAuthSessionItem() {
        return CriOAuthSessionItem.builder()
                .criId(TEST_CRI_ID)
                .criOAuthSessionId(TEST_CRI_OAUTH_SESSION_ID)
                .build();
    }

    private IpvSessionItem buildValidIpvSessionItem() {
        var ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setCriOAuthSessionId(TEST_CRI_OAUTH_SESSION_ID);
        return ipvSessionItem;
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }
}
