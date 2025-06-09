package uk.gov.di.ipv.core.library.cristoringservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsCriResRetrieved;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.enums.CriResourceRetrievedType;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DWP_KBV;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;

public class CriStoringService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final CriResponseService criResponseService;
    private final SessionCredentialsService sessionCredentialsService;
    private final AuditService auditService;
    private final CimitService cimitService;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public CriStoringService(
            ConfigService configService,
            AuditService auditService,
            CriResponseService criResponseService,
            SessionCredentialsService sessionCredentialsService,
            CimitService cimitService) {
        this.configService = configService;
        this.auditService = auditService;
        this.criResponseService = criResponseService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.cimitService = cimitService;
        VcHelper.setConfigService(configService);
    }

    public void recordCriResponse(
            JourneyRequest journeyRequest,
            Cri cri,
            String criOAuthSessionId,
            ClientOAuthSessionItem clientOAuthSessionItem,
            List<String> featureSets)
            throws JsonProcessingException {

        recordCriResponse(
                cri,
                criOAuthSessionId,
                journeyRequest.getIpvSessionId(),
                journeyRequest.getIpAddress(),
                journeyRequest.getDeviceInformation(),
                featureSets,
                clientOAuthSessionItem);
    }

    public void recordCriResponse(
            CriCallbackRequest callbackRequest, ClientOAuthSessionItem clientOAuthSessionItem)
            throws JsonProcessingException {

        recordCriResponse(
                callbackRequest.getCredentialIssuer(),
                callbackRequest.getState(),
                callbackRequest.getIpvSessionId(),
                callbackRequest.getIpAddress(),
                callbackRequest.getDeviceInformation(),
                callbackRequest.getFeatureSet(),
                clientOAuthSessionItem);
    }

    private void recordCriResponse(
            Cri cri,
            String criOAuthSessionId,
            String ipvSessionId,
            String ipAddress,
            String deviceInformation,
            List<String> featureSet,
            ClientOAuthSessionItem clientOAuthSessionItem)
            throws JsonProcessingException {
        var userId = clientOAuthSessionItem.getUserId();

        var vcResponseDto =
                VerifiableCredentialResponseDto.builder()
                        .userId(userId)
                        .credentialStatus(VerifiableCredentialStatus.PENDING.getStatus())
                        .build();

        criResponseService.persistCriResponse(
                clientOAuthSessionItem,
                cri,
                OBJECT_MAPPER.writeValueAsString(vcResponseDto),
                criOAuthSessionId,
                CriResponseService.STATUS_PENDING,
                featureSet);

        var auditEventUser =
                new AuditEventUser(
                        userId,
                        ipvSessionId,
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);

        sendAuditEventForProcessedVcResponse(
                CriResourceRetrievedType.PENDING.getType(), cri, auditEventUser, deviceInformation);
    }

    public void storeVcs(
            Cri cri,
            String ipAddress,
            String deviceInformation,
            List<VerifiableCredential> vcs,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem,
            List<VerifiableCredential> sessionVcs)
            throws VerifiableCredentialException,
                    CiPostMitigationsException,
                    CiPutException,
                    UnrecognisedVotException {
        var userId = clientOAuthSessionItem.getUserId();
        var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

        var auditEventUser =
                new AuditEventUser(
                        userId, ipvSessionItem.getIpvSessionId(), govukSigninJourneyId, ipAddress);

        storeVcs(
                cri,
                ipAddress,
                deviceInformation,
                vcs,
                clientOAuthSessionItem,
                ipvSessionItem,
                sessionVcs,
                auditEventUser);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public void storeVcs(
            Cri cri,
            String ipAddress,
            String deviceInformation,
            List<VerifiableCredential> vcs,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem,
            List<VerifiableCredential> sessionVcs,
            AuditEventUser auditEventUser)
            throws CiPutException,
                    CiPostMitigationsException,
                    VerifiableCredentialException,
                    UnrecognisedVotException {
        var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

        List<VerifiableCredential> mitigationVcList = new ArrayList<>(sessionVcs);

        for (var vc : vcs) {
            if (DWP_KBV.equals(cri)) {
                auditService.sendAuditEvent(
                        AuditEvent.createWithDeviceInformation(
                                AuditEventTypes.IPV_DWP_KBV_CRI_VC_ISSUED,
                                configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser,
                                getExtensionsForAudit(vc, VcHelper.isSuccessfulVc(vc)),
                                new AuditRestrictedDeviceInformation(deviceInformation)));
            }
            auditService.sendAuditEvent(
                    AuditEvent.createWithDeviceInformation(
                            AuditEventTypes.IPV_VC_RECEIVED,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            getExtensionsForAudit(vc, VcHelper.isSuccessfulVc(vc)),
                            new AuditRestrictedDeviceInformation(deviceInformation)));

            if (!clientOAuthSessionItem.isReverification()) {
                mitigationVcList.add(vc);
                cimitService.submitVC(vc, govukSigninJourneyId, ipAddress);
                cimitService.submitMitigatingVcList(
                        mitigationVcList, govukSigninJourneyId, ipAddress);
            }

            if (cri.equals(TICF)) {
                ipvSessionItem.setRiskAssessmentCredential(vc.getVcString());
            } else {
                if (cri.equals(ADDRESS)) {
                    // Remove any existing address VC from session credentials - for 6MFC
                    sessionCredentialsService.deleteSessionCredentialsForCri(
                            ipvSessionItem.getIpvSessionId(), ADDRESS);
                }
                sessionCredentialsService.persistCredentials(
                        List.of(vc), ipvSessionItem.getIpvSessionId(), true);
            }
        }

        sendAuditEventForProcessedVcResponse(
                vcs.isEmpty()
                        ? CriResourceRetrievedType.EMPTY.getType()
                        : CriResourceRetrievedType.VC.getType(),
                cri,
                auditEventUser,
                deviceInformation);
    }

    private void sendAuditEventForProcessedVcResponse(
            String criResourceRetrievedType,
            Cri cri,
            AuditEventUser auditEventUser,
            String deviceInformation) {

        var criId = cri.getId();
        LOGGER.info(
                LogHelper.buildLogMessage(
                                String.format(
                                        "Successfully processed %s CRI credential.",
                                        criResourceRetrievedType))
                        .with(LOG_CRI_ID.getFieldName(), criId));

        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionsCriResRetrieved(criId, criResourceRetrievedType),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }
}
