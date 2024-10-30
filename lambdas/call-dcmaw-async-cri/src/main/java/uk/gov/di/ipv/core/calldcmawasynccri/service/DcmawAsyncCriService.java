package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.dto.AsyncCredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.enums.MobileAppJourneyType;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;

import java.time.Clock;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CONNECTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;

public class DcmawAsyncCriService {
    private static final Logger LOGGER = LogManager.getLogger();

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
                        new SignerFactory(configService),
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
            IpvSessionItem ipvSessionItem,
            MobileAppJourneyType mobileAppJourneyType)
            throws CriApiException, JsonProcessingException, HttpResponseExceptionWithErrorBody {

        String connection = configService.getActiveConnection(DCMAW_ASYNC);

        ipvSessionItem.setCriOAuthSessionId(oauthState);
        ipvSessionService.updateIpvSession(ipvSessionItem);

        var criOAuthSessionItem =
                criOAuthSessionService.persistCriOAuthSession(
                        oauthState,
                        DCMAW_ASYNC,
                        clientOAuthSessionItem.getClientOAuthSessionId(),
                        connection);

        var dcmawAsyncClientSecret =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_CLIENT_OAUTH_SECRET,
                        criOAuthSessionItem.getCriId(),
                        criOAuthSessionItem.getConnection());

        if (dcmawAsyncClientSecret == null) {
            LOGGER.warn(
                    LogHelper.buildLogMessage("DCMAW Async OAuth secret value not found")
                            .with(LOG_CRI_ID.getFieldName(), DCMAW_ASYNC)
                            .with(LOG_CONNECTION.getFieldName(), connection));
        }

        var criConfig = configService.getOauthCriConfig(criOAuthSessionItem);

        var accessToken =
                criApiService.fetchAccessToken(
                        criConfig.getClientId(), dcmawAsyncClientSecret, criOAuthSessionItem);

        // Callback URL only wanted for MAM case where mobile users can return to a valid site
        // session.
        String clientCallbackUrl = null;
        switch (mobileAppJourneyType) {
            case DAD:
                break;
            case MAM:
                clientCallbackUrl = criConfig.getClientCallbackUrl().toString();
                break;
            default:
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.INVALID_PROCESS_MOBILE_APP_JOURNEY_TYPE);
        }

        var credentialRequestBody =
                new AsyncCredentialRequestBodyDto(
                        clientOAuthSessionItem.getUserId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        criConfig.getClientId(),
                        oauthState,
                        clientCallbackUrl);

        return criApiService.fetchVerifiableCredential(
                accessToken, DCMAW_ASYNC, criOAuthSessionItem, credentialRequestBody);
    }
}
