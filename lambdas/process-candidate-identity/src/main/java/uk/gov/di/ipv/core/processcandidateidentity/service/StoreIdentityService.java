package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCandidateIdentityType;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

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

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public void storeIdentity(
            Vot achievedVot,
            String userId,
            CandidateIdentityType identityType,
            String deviceInformation,
            List<VerifiableCredential> credentials,
            AuditEventUser auditEventUser,
            List<EvcsGetUserVCDto> evcsVcs,
            VotMatchingResult.VotAndProfile strongestMatchedVot)
            throws EvcsServiceException {
        if (identityType == CandidateIdentityType.PENDING) {
            evcsService.storePendingIdentity(userId, credentials, evcsVcs, achievedVot);
        } else {
            evcsService.storeCompletedIdentity(
                    userId, credentials, evcsVcs, strongestMatchedVot, achievedVot);
        }

        LOGGER.info(LogHelper.buildLogMessage("Identity successfully stored"));

        sendIdentityStoredEvent(achievedVot, identityType, deviceInformation, auditEventUser);
    }

    private void sendIdentityStoredEvent(
            Vot achievedVot,
            CandidateIdentityType identityType,
            String deviceInformation,
            AuditEventUser auditEventUser) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        IPV_IDENTITY_STORED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionCandidateIdentityType(
                                identityType, achievedVot.equals(P0) ? null : achievedVot),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }
}
