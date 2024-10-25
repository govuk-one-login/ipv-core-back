package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.dto.AsyncCredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
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

    private final AuditService auditService;
    private final ConfigService configService;
    private final CriApiService criApiService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;

    @ExcludeFromGeneratedCoverageReport
    public DcmawAsyncCriService(ConfigService configService) {
        this.configService = configService;
        this.auditService = AuditService.create(configService);
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
            AuditService auditService,
            ConfigService configService,
            CriApiService criApiService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService) {
        this.configService = configService;
        this.criApiService = criApiService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.auditService = auditService;
    }

    public VerifiableCredentialResponse startDcmawAsyncSession(
            String oauthState,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws CriApiException, JsonProcessingException {

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

        var credentialRequestBody =
                new AsyncCredentialRequestBodyDto(
                        clientOAuthSessionItem.getUserId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        criConfig.getClientId(),
                        oauthState,
                        criConfig.getClientCallbackUrl().toString());

        return criApiService.fetchVerifiableCredential(
                accessToken, DCMAW_ASYNC, criOAuthSessionItem, credentialRequestBody);
    }

    public void sendAuditEventForAppHandoff(
            JourneyRequest journeyRequest,
            ClientOAuthSessionItem clientOAuthSessionItem) {

        var auditEventUser =
                new AuditEventUser(
                        clientOAuthSessionItem.getUserId(),
                        journeyRequest.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        journeyRequest.getIpAddress());

        LOGGER.info("Sending app handoff audit event");

        auditService.sendAuditEvent(
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_APP_HANDOFF_START,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));
    }
}
