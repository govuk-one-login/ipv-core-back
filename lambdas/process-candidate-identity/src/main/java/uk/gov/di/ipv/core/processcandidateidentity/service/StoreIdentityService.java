package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCandidateIdentityType;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.ipv.core.processcandidateidentity.domain.SharedAuditEventParameters;

import java.util.List;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.STORED_IDENTITY_SERVICE;

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
            String userId,
            List<VerifiableCredential> sessionCredentials,
            List<EvcsGetUserVCDto> evcsVcs,
            Vot achievedVot,
            VotMatchingResult.VotAndProfile strongestMatchedVot,
            CandidateIdentityType identityType,
            SharedAuditEventParameters auditEventParameters)
            throws EvcsServiceException {

        var hasStoredSiObject = false;
        var isPendingIdentity = identityType.equals(CandidateIdentityType.PENDING);
        LOGGER.info(LogHelper.buildLogMessage("Storing user VCs with POST"));
        evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                userId, sessionCredentials, evcsVcs, isPendingIdentity);

        if (configService.enabled(STORED_IDENTITY_SERVICE) && !isPendingIdentity) {
            try {
                var httpResponse =
                        evcsService.storeStoredIdentityRecord(
                                userId, sessionCredentials, strongestMatchedVot, achievedVot);
                hasStoredSiObject = httpResponse.statusCode() == HttpStatusCode.ACCEPTED;
            } catch (FailedToCreateStoredIdentityForEvcsException e) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                "Failed to create stored identity record. Stored identity record was not saved to EVCS."));
            } catch (EvcsServiceException e) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                "Failed to store stored identity record to EVCS. Continuing user journey."));
            }
        }

        LOGGER.info(LogHelper.buildLogMessage("Identity successfully stored"));

        sendIdentityStoredEvent(
                strongestMatchedVot, identityType, auditEventParameters, hasStoredSiObject);
    }

    private void sendIdentityStoredEvent(
            VotMatchingResult.VotAndProfile strongestMatchedVot,
            CandidateIdentityType identityType,
            SharedAuditEventParameters auditEventParameters,
            boolean isSiRecordCreated) {

        var vot = Objects.isNull(strongestMatchedVot) ? null : strongestMatchedVot.vot();

        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        IPV_IDENTITY_STORED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventParameters.auditEventUser(),
                        new AuditExtensionCandidateIdentityType(
                                identityType, isSiRecordCreated, vot),
                        new AuditRestrictedDeviceInformation(
                                auditEventParameters.deviceInformation())));
    }
}
