package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.dto.AsyncCredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;

import java.time.Clock;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;

public class DcmawAsyncCriService {
    private final ConfigService configService;
    private final CriApiService criApiService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;

    @ExcludeFromGeneratedCoverageReport
    public DcmawAsyncCriService(ConfigService configService) {
        this.configService = configService;
        this.criApiService =
                new CriApiService(
                        configService,
                        new KmsEs256SignerFactory(),
                        SecureTokenHelper.getInstance(),
                        Clock.systemDefaultZone());
        this.ipvSessionService = new IpvSessionService(configService);
        this.criOAuthSessionService = new CriOAuthSessionService(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public DcmawAsyncCriService(
            ConfigService configService,
            CriApiService criApiService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService) {
        this.configService = configService;
        this.criApiService = criApiService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
    }

    public VerifiableCredentialResponse startDcmawAsyncSession(
            String oauthState,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws CriApiException, JsonProcessingException {
        final String criId = DCMAW_ASYNC.getId();
        String connection = configService.getActiveConnection(criId);

        ipvSessionItem.setCriOAuthSessionId(oauthState);
        ipvSessionService.updateIpvSession(ipvSessionItem);

        var criOAuthSessionItem =
                criOAuthSessionService.persistCriOAuthSession(
                        oauthState,
                        criId,
                        clientOAuthSessionItem.getClientOAuthSessionId(),
                        connection);

        String dcmawAsyncClientSecret = configService.getCriOAuthClientSecret(criOAuthSessionItem);
        var criConfig = configService.getOauthCriConfig(criOAuthSessionItem);

        var accessToken =
                criApiService.fetchAccessToken(
                        criConfig.getClientId(), dcmawAsyncClientSecret, criOAuthSessionItem);

        var credentialRequestBody =
                new AsyncCredentialRequestBodyDto(
                        clientOAuthSessionItem.getUserId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        criConfig.getClientId(),
                        oauthState,
                        criConfig.getClientCallbackUrl().toString());

        return criApiService.fetchVerifiableCredential(
                accessToken, criId, criOAuthSessionItem, credentialRequestBody);
    }
}
