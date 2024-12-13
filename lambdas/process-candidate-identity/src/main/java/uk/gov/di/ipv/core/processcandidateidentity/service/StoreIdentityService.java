package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionIdentityType;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.EvcsService;

import java.util.List;

import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;

public class StoreIdentityService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final AuditService auditService;
    private final EvcsService evcsService;

    @ExcludeFromGeneratedCoverageReport
    public StoreIdentityService(ConfigService configService, AuditService auditService) {
        this.configService = configService;
        this.auditService = auditService;
        this.evcsService = new EvcsService(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public StoreIdentityService(
            ConfigService configService, AuditService auditService, EvcsService evcsService) {
        this.configService = configService;
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
            throws EvcsServiceException {
        String userId = clientOAuthSessionItem.getUserId();

        if (identityType == IdentityType.PENDING) {
            evcsService.storePendingIdentity(
                    userId, credentials, clientOAuthSessionItem.getEvcsAccessToken());
        } else {
            evcsService.storeCompletedIdentity(
                    userId, credentials, clientOAuthSessionItem.getEvcsAccessToken());
        }

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
