package uk.gov.di.ipv.core.library.cristoringservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsCriResRetrieved;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.enums.CriResourceRetrievedType;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.List;

import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;

public class CriStoringService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final CriResponseService criResponseService;
    private final SessionCredentialsService sessionCredentialsService;
    private final AuditService auditService;
    private final CiMitService ciMitService;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public CriStoringService(
            ConfigService configService,
            AuditService auditService,
            CriResponseService criResponseService,
            SessionCredentialsService sessionCredentialsService,
            CiMitService ciMitService) {
        this.configService = configService;
        this.auditService = auditService;
        this.criResponseService = criResponseService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.ciMitService = ciMitService;
        VcHelper.setConfigService(configService);
    }

    public void storeCriResponse(
            CriCallbackRequest callbackRequest, ClientOAuthSessionItem clientOAuthSessionItem)
            throws JsonProcessingException, SqsException {
        var criId = callbackRequest.getCredentialIssuerId();
        var criOAuthSessionId = callbackRequest.getState();
        var userId = clientOAuthSessionItem.getUserId();

        var auditEventUser =
                new AuditEventUser(
                        userId,
                        callbackRequest.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        callbackRequest.getIpAddress());

        var vcResponseDto =
                VerifiableCredentialResponseDto.builder()
                        .userId(userId)
                        .credentialStatus(VerifiableCredentialStatus.PENDING.getStatus())
                        .build();

        criResponseService.persistCriResponse(
                userId,
                criId,
                OBJECT_MAPPER.writeValueAsString(vcResponseDto),
                criOAuthSessionId,
                CriResponseService.STATUS_PENDING);

        sendAuditEventForProcessedVcResponse(
                CriResourceRetrievedType.PENDING.getType(),
                criId,
                auditEventUser,
                callbackRequest.getDeviceInformation());
    }

    public void storeVcs(
            String criId,
            String ipAddress,
            String deviceInformation,
            List<VerifiableCredential> vcs,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws SqsException, CiPutException, CiPostMitigationsException,
                    VerifiableCredentialException, UnrecognisedVotException,
                    CredentialParseException {
        var userId = clientOAuthSessionItem.getUserId();
        var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

        var auditEventUser =
                new AuditEventUser(
                        userId, ipvSessionItem.getIpvSessionId(), govukSigninJourneyId, ipAddress);

        for (var vc : vcs) {
            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_VC_RECEIVED,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            getExtensionsForAudit(vc, VcHelper.isSuccessfulVc(vc)),
                            new AuditRestrictedDeviceInformation(deviceInformation)));

            // TODO PYIC-6658: use scope constants when PYIC-6089 is merged
            if (!clientOAuthSessionItem.getScope().equals("reverification")) {
                ciMitService.submitVC(vc, govukSigninJourneyId, ipAddress);
                ciMitService.submitMitigatingVcList(List.of(vc), govukSigninJourneyId, ipAddress);
            }

            if (criId.equals(TICF_CRI)) {
                ipvSessionItem.setRiskAssessmentCredential(vc.getVcString());
            } else {
                if (criId.equals(ADDRESS_CRI)) {
                    // Remove any existing address VC from session credentials - for 6MFC
                    sessionCredentialsService.deleteSessionCredentialsForCri(
                            ipvSessionItem.getIpvSessionId(), ADDRESS_CRI);
                }
                sessionCredentialsService.persistCredentials(
                        List.of(vc), ipvSessionItem.getIpvSessionId(), true);
            }
        }

        sendAuditEventForProcessedVcResponse(
                vcs.isEmpty()
                        ? CriResourceRetrievedType.EMPTY.getType()
                        : CriResourceRetrievedType.VC.getType(),
                criId,
                auditEventUser,
                deviceInformation);
    }

    private void sendAuditEventForProcessedVcResponse(
            String criResourceRetrievedType,
            String criId,
            AuditEventUser auditEventUser,
            String deviceInformation)
            throws SqsException {
        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_LAMBDA_RESULT.getFieldName(),
                                String.format(
                                        "Successfully processed %s CRI credential.",
                                        criResourceRetrievedType))
                        .with(LOG_CRI_ID.getFieldName(), criId));

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionsCriResRetrieved(criId, criResourceRetrievedType),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }
}
