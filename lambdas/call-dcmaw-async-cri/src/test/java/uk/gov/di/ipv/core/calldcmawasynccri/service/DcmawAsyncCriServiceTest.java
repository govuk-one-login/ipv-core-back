package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.MobileAppJourneyType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_CLIENT_OAUTH_SECRET;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;

@ExtendWith(MockitoExtension.class)
class DcmawAsyncCriServiceTest {
    private static final String IPV_SESSION_ID = "ipv-session-id";
    private static final String CRI_OAUTH_STATE = "cri-oauth-state";
    public static final String TEST_SECRET = "test-secret";
    public static final String CRI_CLIENT_ID = "cri-client-id";
    public static final String AUTHORIZE_URL = "https://example.com/authorize";
    public static final String CREDENTIAL_URL = "https://example.com/credentialbackUrl";
    public static final String TOKEN_URL = "https://example.com/tokenUrl";
    private static final String REDIRECT_URL = "https://example.com/callbackUrl";
    public static final String TEST_ENCRYPTION = "test-secret";
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String USER_ID = "userId";
    public static final String JOURNEY_ID = "journeyId";
    public static final String CLIENT_OAUTH_SESSION_ID = "client-oauth-session-id";
    public static final String CONNECTION = "connection";

    @Mock private ConfigService mockConfigService;
    @Mock private CriApiService mockCriApiService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private AuditService auditService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;

    @InjectMocks private DcmawAsyncCriService dcmawAsyncCriService;

    @ParameterizedTest
    @MethodSource("mobileAppJourneyTypesAndClientCallbackUrls")
    void startDcmawAsyncSession_WhenCalled_ReturnsAVc(
            MobileAppJourneyType mobileAppJourneyType, String expectedRedirectUrl)
            throws Exception {
        // Arrange
        var clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .userId(USER_ID)
                        .govukSigninJourneyId(JOURNEY_ID)
                        .clientOAuthSessionId(CLIENT_OAUTH_SESSION_ID)
                        .build();

        var ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setVot(Vot.P2);
        ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

        var criConfig =
                OauthCriConfig.builder()
                        .tokenUrl(new URI(TOKEN_URL))
                        .authorizeUrl(new URI(AUTHORIZE_URL))
                        .credentialUrl(new URI(CREDENTIAL_URL))
                        .clientId(CRI_CLIENT_ID)
                        .clientCallbackUrl(URI.create(REDIRECT_URL))
                        .requiresApiKey(false)
                        .requiresAdditionalEvidence(false)
                        .encryptionKey(TEST_ENCRYPTION)
                        .build();

        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criId(DCMAW_ASYNC.getId())
                        .criOAuthSessionId(CRI_OAUTH_STATE)
                        .clientOAuthSessionId(CLIENT_OAUTH_SESSION_ID)
                        .connection(CONNECTION)
                        .build();

        when(mockCriOAuthSessionService.persistCriOAuthSession(
                        CRI_OAUTH_STATE, DCMAW_ASYNC, CLIENT_OAUTH_SESSION_ID, CONNECTION))
                .thenReturn(criOAuthSessionItem);

        when(mockConfigService.getOauthCriConfig(criOAuthSessionItem)).thenReturn(criConfig);
        when(mockConfigService.getSecret(
                        CREDENTIAL_ISSUER_CLIENT_OAUTH_SECRET, DCMAW_ASYNC.getId(), CONNECTION))
                .thenReturn(TEST_SECRET);
        when(mockConfigService.getActiveConnection(DCMAW_ASYNC)).thenReturn(CONNECTION);

        var accessToken = new BearerAccessToken(ACCESS_TOKEN);
        when(mockCriApiService.fetchAccessToken(CRI_CLIENT_ID, TEST_SECRET, criOAuthSessionItem))
                .thenReturn(accessToken);

        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(USER_ID)
                        .credentialStatus(VerifiableCredentialStatus.PENDING)
                        .build();
        when(mockCriApiService.fetchVerifiableCredential(
                        argThat(bat -> ACCESS_TOKEN.equals(bat.getValue())),
                        eq(DCMAW_ASYNC),
                        eq(criOAuthSessionItem),
                        argThat(
                                crbd ->
                                        USER_ID.equals(crbd.getUserId())
                                                && JOURNEY_ID.equals(crbd.getJourneyId())
                                                && CRI_CLIENT_ID.equals(crbd.getClientId())
                                                && CRI_OAUTH_STATE.equals(crbd.getState())
                                                && Objects.equals(
                                                        expectedRedirectUrl,
                                                        crbd.getRedirectUri()))))
                .thenReturn(vcResponse);

        // Act
        var response =
                dcmawAsyncCriService.startDcmawAsyncSession(
                        CRI_OAUTH_STATE,
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        mobileAppJourneyType);

        // Assert
        assertEquals(vcResponse, response);
    }

    @Test
    void sendAuditEventForAppHandoff_WhenCalled_RaisesAnAuditEvent() {
        var journeyRequest =
                JourneyRequest.builder()
                        .ipvSessionId("ipvSessionId")
                        .ipAddress("ipAddress")
                        .deviceInformation("deviceInformation")
                        .build();
        var clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .userId("userId")
                        .govukSigninJourneyId("journeyId")
                        .build();

        // Act
        dcmawAsyncCriService.sendAuditEventForAppHandoff(journeyRequest, clientOAuthSessionItem);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_APP_HANDOFF_START, auditEvent.getEventName());
        assertEquals("ipvSessionId", auditEvent.getUser().getSessionId());
        assertEquals("ipAddress", auditEvent.getUser().getIpAddress());
        assertEquals(
                "deviceInformation",
                ((AuditRestrictedDeviceInformation) auditEvent.getRestricted())
                        .deviceInformation()
                        .getEncoded());
        assertEquals("userId", auditEvent.getUser().getUserId());
        assertEquals("journeyId", auditEvent.getUser().getGovukSigninJourneyId());
    }

    private static Stream<Arguments> mobileAppJourneyTypesAndClientCallbackUrls() {
        return Stream.of(
                Arguments.of(MobileAppJourneyType.MAM, REDIRECT_URL),
                Arguments.of(MobileAppJourneyType.DAD, null));
    }
}
