package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;

@ExtendWith(MockitoExtension.class)
class DcmawAsyncCriServiceTest {
    private static final String IPV_SESSION_ID = "ipv-session-id";
    private static final String CRI_OAUTH_STATE = "cri-oauth-state";
    public static final String TEST_SECRET = "test-secret";
    public static final String CRI_CLIENT_ID = "cri-client-id";
    public static final String CREDENTIAL_URL = "https://example.com/credentialbackUrl";
    public static final String TOKEN_URL = "https://example.com/tokenUrl";
    private static final String REDIRECT_URL = "https://example.com/callbackUrl";
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String USER_ID = "userId";
    public static final String JOURNEY_ID = "journeyId";
    public static final String CLIENT_OAUTH_SESSION_ID = "client-oauth-session-id";
    public static final String CONNECTION = "connection";

    @Mock private ConfigService mockConfigService;
    @Mock private CriApiService mockCriApiService;

    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;

    @InjectMocks private DcmawAsyncCriService dcmawAsyncCriService;

    @Test
    void startDcmawAsyncSession_WhenCalled_ReturnsAVc() throws Exception {
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
                        .credentialUrl(new URI(CREDENTIAL_URL))
                        .clientId(CRI_CLIENT_ID)
                        .clientCallbackUrl(URI.create(REDIRECT_URL))
                        .requiresApiKey(false)
                        .requiresAdditionalEvidence(false)
                        .build();

        var criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criId(DCMAW_ASYNC.getId())
                        .criOAuthSessionId(CRI_OAUTH_STATE)
                        .clientOAuthSessionId(CLIENT_OAUTH_SESSION_ID)
                        .build();

        when(mockCriOAuthSessionService.persistCriOAuthSession(
                        CRI_OAUTH_STATE, DCMAW_ASYNC, CLIENT_OAUTH_SESSION_ID, CONNECTION))
                .thenReturn(criOAuthSessionItem);

        when(mockConfigService.getOauthCriConfig(criOAuthSessionItem)).thenReturn(criConfig);
        when(mockConfigService.getCriOAuthClientSecret(criOAuthSessionItem))
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
                                                && REDIRECT_URL.equals(crbd.getRedirectUri()))))
                .thenReturn(vcResponse);

        // Act
        var response =
                dcmawAsyncCriService.startDcmawAsyncSession(
                        CRI_OAUTH_STATE, clientOAuthSessionItem, ipvSessionItem);

        // Assert
        assertEquals(vcResponse, response);
    }
}
