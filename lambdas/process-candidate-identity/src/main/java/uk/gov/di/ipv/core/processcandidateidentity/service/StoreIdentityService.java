package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCandidateIdentityType;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.util.List;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;

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

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public void storeIdentity(
            ClientOAuthSessionItem clientOAuthSessionItem,
            CandidateIdentityType identityType,
            String deviceInformation,
            List<VerifiableCredential> credentials,
            AuditEventUser auditEventUser,
            List<EvcsGetUserVCDto> evcsVcs,
            VotMatchingResult matchingVot)
            throws EvcsServiceException {
        if (identityType == CandidateIdentityType.PENDING) {
            evcsService.storePendingIdentity(clientOAuthSessionItem, credentials, evcsVcs);
        } else {
            evcsService.storeCompletedIdentity(
                    clientOAuthSessionItem, credentials, evcsVcs, matchingVot);
        }

        LOGGER.info(LogHelper.buildLogMessage("Identity successfully stored"));

        sendIdentityStoredEvent(identityType, deviceInformation, auditEventUser, matchingVot);
    }

    private void sendIdentityStoredEvent(
            CandidateIdentityType identityType,
            String deviceInformation,
            AuditEventUser auditEventUser,
            VotMatchingResult matchingVot) {

        var vot =
                Objects.isNull(matchingVot)
                        ? null
                        : matchingVot
                                .strongestMatch()
                                .map(VotMatchingResult.VotAndProfile::vot)
                                .orElse(null);

        boolean sisRecordCreated =
                configService.enabled(CoreFeatureFlag.STORED_IDENTITY_SERVICE)
                        && identityType != CandidateIdentityType.PENDING;

        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        IPV_IDENTITY_STORED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionCandidateIdentityType(
                                identityType, vot, sisRecordCreated),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }
}
