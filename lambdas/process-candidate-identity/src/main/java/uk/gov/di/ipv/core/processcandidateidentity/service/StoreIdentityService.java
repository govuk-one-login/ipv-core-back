package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionIdentityType;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IDENTITY_STORED_PATH;

public class StoreIdentityService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> JOURNEY_IDENTITY_STORED =
            new JourneyResponse(JOURNEY_IDENTITY_STORED_PATH).toObjectMap();
    private final ConfigService configService;
    private final SessionCredentialsService sessionCredentialsService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final AuditService auditService;
    private final EvcsService evcsService;

    @ExcludeFromGeneratedCoverageReport
    public StoreIdentityService(ConfigService configService, AuditService auditService) {
        this.configService = configService;
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = auditService;
        this.evcsService = new EvcsService(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public StoreIdentityService(
            ConfigService configService,
            SessionCredentialsService sessionCredentialsService,
            VerifiableCredentialService verifiableCredentialService,
            AuditService auditService,
            EvcsService evcsService) {
        this.configService = configService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.auditService = auditService;
        this.evcsService = evcsService;
    }

    public void storeIdentity(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IdentityType identityType,
            String deviceInformation,
            String ipAddress,
            List<VerifiableCredential> credentials)
            throws VerifiableCredentialException, EvcsServiceException {
        String userId = clientOAuthSessionItem.getUserId();

        if (configService.enabled(EVCS_WRITE_ENABLED)) {
            try {
                if (identityType != IdentityType.PENDING) {
                    evcsService.storeCompletedIdentity(
                            userId, credentials, clientOAuthSessionItem.getEvcsAccessToken());
                } else {
                    evcsService.storePendingIdentity(
                            userId, credentials, clientOAuthSessionItem.getEvcsAccessToken());
                }
                credentials.forEach(credential -> credential.setMigrated(Instant.now()));
            } catch (EvcsServiceException e) {
                if (configService.enabled(EVCS_READ_ENABLED)) {
                    throw e;
                } else {
                    LOGGER.error(LogHelper.buildErrorMessage("Failed to store EVCS identity", e));
                }
            }
        }

        verifiableCredentialService.storeIdentity(credentials, userId);

        LOGGER.info(LogHelper.buildLogMessage("Identity successfully stored"));

        sendIdentityStoredEvent(
                ipvSessionItem, clientOAuthSessionItem, identityType, ipAddress, deviceInformation);
    }

    private void sendIdentityStoredEvent(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IdentityType identityType,
            String ipAddress,
            String deviceInformation) {
        Vot vot = ipvSessionItem.getVot();
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        IPV_IDENTITY_STORED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        new AuditEventUser(
                                clientOAuthSessionItem.getUserId(),
                                ipvSessionItem.getIpvSessionId(),
                                clientOAuthSessionItem.getGovukSigninJourneyId(),
                                ipAddress),
                        new AuditExtensionIdentityType(identityType, vot.equals(P0) ? null : vot),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }
}
