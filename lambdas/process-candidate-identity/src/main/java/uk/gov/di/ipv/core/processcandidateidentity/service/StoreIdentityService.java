package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCandidateIdentityType;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
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
            throws EvcsServiceException, FailedToCreateStoredIdentityForEvcsException {

        var govukSigninJourneyId = auditEventParameters.auditEventUser().getGovukSigninJourneyId();
        var isPendingIdentity = identityType.equals(CandidateIdentityType.PENDING);
        var hasStoredSiObject = false;

        if (configService.enabled(CoreFeatureFlag.EVCS_API_UPDATES)) {
            hasStoredSiObject =
                    storeIdentityUpdated(
                            userId,
                            govukSigninJourneyId,
                            sessionCredentials,
                            evcsVcs,
                            achievedVot,
                            strongestMatchedVot,
                            isPendingIdentity);
        } else {
            hasStoredSiObject =
                    storeIdentityLegacy(
                            userId,
                            sessionCredentials,
                            evcsVcs,
                            achievedVot,
                            strongestMatchedVot,
                            isPendingIdentity);
        }

        LOGGER.info(LogHelper.buildLogMessage("Identity successfully stored"));
        sendIdentityStoredEvent(
                strongestMatchedVot, identityType, auditEventParameters, hasStoredSiObject);
    }

    private boolean storeIdentityUpdated(
            String userId,
            String govukSigninJourneyId,
            List<VerifiableCredential> sessionCredentials,
            List<EvcsGetUserVCDto> evcsVcs,
            Vot achievedVot,
            VotMatchingResult.VotAndProfile strongestMatchedVot,
            boolean isPendingIdentity)
            throws EvcsServiceException, FailedToCreateStoredIdentityForEvcsException {

        if (isPendingIdentity) {
            LOGGER.info(LogHelper.buildLogMessage("Storing user VCs with POST"));
            evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                    userId, sessionCredentials, evcsVcs, true);
            return false;
        }

        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Storing user identity records and VCs in one transaction."));
        var response =
                evcsService.storeStoredIdentityRecordAndVcs(
                        userId,
                        govukSigninJourneyId,
                        sessionCredentials,
                        evcsVcs,
                        strongestMatchedVot,
                        achievedVot);

        return response.statusCode() == HttpStatusCode.ACCEPTED;
    }

    private boolean storeIdentityLegacy(
            String userId,
            List<VerifiableCredential> sessionCredentials,
            List<EvcsGetUserVCDto> evcsVcs,
            Vot achievedVot,
            VotMatchingResult.VotAndProfile strongestMatchedVot,
            boolean isPendingIdentity)
            throws EvcsServiceException {

        LOGGER.info(LogHelper.buildLogMessage("Storing user VCs with POST"));
        evcsService.storeCompletedOrPendingIdentityWithPostVcs(
                userId, sessionCredentials, evcsVcs, isPendingIdentity);

        if (isPendingIdentity) {
            return false;
        }

        try {
            var response =
                    evcsService.storeStoredIdentityRecord(
                            userId, sessionCredentials, strongestMatchedVot, achievedVot);
            return response.statusCode() == HttpStatusCode.ACCEPTED;
        } catch (FailedToCreateStoredIdentityForEvcsException e) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "Failed to create stored identity record. Stored identity record was not saved to EVCS."));
        } catch (EvcsServiceException e) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "Failed to store stored identity record to EVCS. Continuing user journey."));
        }

        return false;
    }

    private void sendIdentityStoredEvent(
            VotMatchingResult.VotAndProfile strongestMatchedVot,
            CandidateIdentityType identityType,
            SharedAuditEventParameters auditEventParameters,
            boolean isSiRecordCreated) {

        var maxVot = Objects.isNull(strongestMatchedVot) ? null : strongestMatchedVot.vot();

        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        IPV_IDENTITY_STORED,
                        configService.getComponentId(),
                        auditEventParameters.auditEventUser(),
                        new AuditExtensionCandidateIdentityType(
                                identityType, isSiRecordCreated, maxVot, maxVot),
                        new AuditRestrictedDeviceInformation(
                                auditEventParameters.deviceInformation())));
    }
}
