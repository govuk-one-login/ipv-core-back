package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@ExtendWith(MockitoExtension.class)
class DcmawAsyncCriServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String SESSION_ID = "session-id";
    private static final String OAUTH_STATE = "oauth-state";

    private IpvSessionItem ipvSessionItem;
    @Mock private OauthCriConfig criConfig;
    @Mock private ConfigService mockConfigService;
    private static final String TEST_REDIRECT_URI = "http:example.com/callback/criId";
    @Mock private CriApiService mockCriApiService;

    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;

    @InjectMocks private DcmawAsyncCriService dcmawAsyncCriService;

    @BeforeEach
    void setUp() {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setVot(Vot.P2);
        ipvSessionItem.setIpvSessionId(SESSION_ID);
    }

    @Test
    void testStartDcmawAsyncSession() throws Exception {
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        var vcResponse =
                VerifiableCredentialResponse.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .verifiableCredentials(
                                List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString()))
                        .credentialStatus(VerifiableCredentialStatus.CREATED)
                        .build();

        when(mockCriApiService.fetchVerifiableCredential(any(), any(), any(), any()))
                .thenReturn(vcResponse);
        when(criConfig.getClientCallbackUrl()).thenReturn(URI.create(TEST_REDIRECT_URI));

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(criConfig);
        when(mockConfigService.getCriOAuthClientSecret(any())).thenReturn("clientSecret");

        BearerAccessToken accessToken = new BearerAccessToken("accessToken");
        when(mockCriApiService.fetchAccessToken(any(), any(), any())).thenReturn(accessToken);

        dcmawAsyncCriService.startDcmawAsyncSession(
                OAUTH_STATE, clientOAuthSessionItem, ipvSessionItem);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        verify(mockCriOAuthSessionService).persistCriOAuthSession(any(), any(), any(), any());
        verify(mockCriApiService).fetchVerifiableCredential(any(), any(), any(), any());
    }

    @Test
    void testStartDcmawAsyncSessionThrowsCriApiException() throws Exception {
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(criConfig);

        when(mockCriApiService.fetchAccessToken(any(), any(), any()))
                .thenThrow(
                        new CriApiException(
                                HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST));

        assertThrows(
                CriApiException.class,
                () ->
                        dcmawAsyncCriService.startDcmawAsyncSession(
                                OAUTH_STATE, clientOAuthSessionItem, ipvSessionItem));
    }

    @Test
    void testStartDcmawAsyncSessionThrowsJsonProcessingException() throws Exception {
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(criConfig);
        when(criConfig.getClientCallbackUrl()).thenReturn(URI.create(TEST_REDIRECT_URI));
        BearerAccessToken accessToken = new BearerAccessToken("accessToken");
        when(mockCriApiService.fetchAccessToken(any(), any(), any())).thenReturn(accessToken);

        when(mockCriApiService.fetchVerifiableCredential(any(), any(), any(), any()))
                .thenThrow(new JsonProcessingException("error") {});

        assertThrows(
                JsonProcessingException.class,
                () ->
                        dcmawAsyncCriService.startDcmawAsyncSession(
                                OAUTH_STATE, clientOAuthSessionItem, ipvSessionItem));
    }
}
