package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCoiCheck;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedCheckCoi;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.auditing.restricted.DeviceInformation;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.ReverificationFailureCode;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.processcandidateidentity.domain.SharedAuditEventParameters;
import uk.gov.di.model.PostalAddress;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.Boolean.TRUE;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.ACCOUNT_INTERVENTION;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CHECK_TYPE;

public class CheckCoiService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;
    private final UserIdentityService userIdentityService;
    private final EvcsService evcsService;

    @ExcludeFromGeneratedCoverageReport
    public CheckCoiService(ConfigService configService, AuditService auditService) {
        this.configService = configService;
        this.auditService = auditService;
        this.ipvSessionService = new IpvSessionService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.evcsService = new EvcsService(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckCoiService(
            ConfigService configService,
            AuditService auditService,
            IpvSessionService ipvSessionService,
            UserIdentityService userIdentityService,
            EvcsService evcsService) {
        this.configService = configService;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
        this.userIdentityService = userIdentityService;
        this.evcsService = evcsService;
    }

    public boolean isCoiCheckSuccessful(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSession,
            CoiCheckType checkType,
            List<VerifiableCredential> sessionVcs,
            List<EvcsGetUserVCDto> evcsUserVcs,
            SharedAuditEventParameters sharedAuditEventParameters)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {

        var userId = clientOAuthSession.getUserId();

        if (TRUE.equals(clientOAuthSession.getReproveIdentity())) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Reprove identity flag set - checking full name and DOB"));
            checkType = ACCOUNT_INTERVENTION;
        }

        sendAuditEvent(
                AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                checkType,
                null,
                null,
                null,
                sharedAuditEventParameters);

        var oldVcs = evcsService.getVerifiableCredentials(userId, evcsUserVcs, CURRENT);
        var combinedCredentials = Stream.concat(oldVcs.stream(), sessionVcs.stream()).toList();
        var successfulCheck =
                switch (checkType) {
                    case STANDARD ->
                            userIdentityService.areNamesAndDobCorrelated(combinedCredentials);
                    case REVERIFICATION ->
                            userIdentityService.areNamesAndDobCorrelatedForReverification(
                                    combinedCredentials);
                    case ACCOUNT_INTERVENTION ->
                            userIdentityService.areVcsCorrelated(combinedCredentials);
                };

        sendAuditEvent(
                AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                checkType,
                successfulCheck,
                oldVcs,
                sessionVcs,
                sharedAuditEventParameters);

        if (clientOAuthSession.isReverification()) {
            ipvSessionItem.setReverificationStatus(
                    successfulCheck ? ReverificationStatus.SUCCESS : ReverificationStatus.FAILED);

            if (!successfulCheck) {
                ipvSessionItem.setFailureCode(ReverificationFailureCode.IDENTITY_DID_NOT_MATCH);
            }

            ipvSessionService.updateIpvSession(ipvSessionItem);
        }

        if (!successfulCheck) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Failed COI check")
                            .with(LOG_CHECK_TYPE.getFieldName(), checkType));
            return false;
        }

        LOGGER.info(
                LogHelper.buildLogMessage("Successful COI check")
                        .with(LOG_CHECK_TYPE.getFieldName(), checkType));

        return true;
    }

    private void sendAuditEvent(
            AuditEventTypes auditEventType,
            CoiCheckType coiCheckType,
            Boolean coiCheckSuccess,
            List<VerifiableCredential> oldVcs,
            List<VerifiableCredential> sessionsVcs,
            SharedAuditEventParameters sharedAuditEventParameters)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        var deviceInformation = sharedAuditEventParameters.deviceInformation();
        var auditEventUser = sharedAuditEventParameters.auditEventUser();

        var restrictedData =
                auditEventType == AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END
                        ? getRestrictedCheckCoiAuditData(oldVcs, sessionsVcs, deviceInformation)
                        : new AuditRestrictedDeviceInformation(deviceInformation);

        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        auditEventType,
                        configService.getConfiguration().getSelf().getComponentId().toString(),
                        auditEventUser,
                        new AuditExtensionCoiCheck(coiCheckType, coiCheckSuccess),
                        restrictedData));
    }

    private AuditRestrictedCheckCoi getRestrictedCheckCoiAuditData(
            List<VerifiableCredential> oldVcs,
            List<VerifiableCredential> sessionVcs,
            String deviceInformation)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {

        var oldIdentityClaim = userIdentityService.findIdentityClaim(oldVcs);
        var sessionIdentityClaim = userIdentityService.findIdentityClaim(sessionVcs);

        Optional<List<PostalAddress>> oldAddressClaim = userIdentityService.getAddressClaim(oldVcs);
        Optional<List<PostalAddress>> sessionAddressClaim =
                userIdentityService.getAddressClaim(sessionVcs);

        return new AuditRestrictedCheckCoi(
                oldIdentityClaim.map(IdentityClaim::getName).orElse(null),
                sessionIdentityClaim.map(IdentityClaim::getName).orElse(null),
                oldIdentityClaim.map(IdentityClaim::getBirthDate).orElse(null),
                sessionIdentityClaim.map(IdentityClaim::getBirthDate).orElse(null),
                oldAddressClaim.orElse(null),
                sessionAddressClaim.orElse(null),
                new DeviceInformation(deviceInformation));
    }
}
