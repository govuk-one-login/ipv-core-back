package uk.gov.di.ipv.core.processcricallback.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsCriResRetrieved;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.processcricallback.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.processcricallback.enums.CriResourceRetrievedType;

import java.text.ParseException;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;

public class CriStoringService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String EVIDENCE = "evidence";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final CriResponseService criResponseService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final AuditService auditService;
    private final CiMitService ciMitService;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public CriStoringService(
            ConfigService configService,
            AuditService auditService,
            CriResponseService criResponseService,
            VerifiableCredentialService verifiableCredentialService,
            CiMitService ciMitService) {
        this.configService = configService;
        this.auditService = auditService;
        this.criResponseService = criResponseService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.ciMitService = ciMitService;
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

        VerifiableCredentialResponseDto vcResponseDto =
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
                CriResourceRetrievedType.PENDING.getType(), criId, auditEventUser);
    }

    public void storeCreatedVcs(
            VerifiableCredentialResponse vcResponse,
            CriCallbackRequest callbackRequest,
            ClientOAuthSessionItem clientOAuthSessionItem)
            throws SqsException, ParseException, JsonProcessingException, CiPutException,
                    CiPostMitigationsException {
        var criId = callbackRequest.getCredentialIssuerId();
        var ipAddress = callbackRequest.getIpAddress();
        var userId = clientOAuthSessionItem.getUserId();
        var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

        var auditEventUser =
                new AuditEventUser(
                        userId,
                        callbackRequest.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);

        var vcs = vcResponse.getVerifiableCredentials();

        for (SignedJWT vc : vcs) {
            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_VC_RECEIVED,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            getAuditExtensions(vc, VcHelper.isSuccessfulVc(vc))));

            ciMitService.submitVC(vc, govukSigninJourneyId, ipAddress);
            ciMitService.submitMitigatingVcList(
                    List.of(vc.serialize()), govukSigninJourneyId, ipAddress);

            verifiableCredentialService.persistUserCredentials(vc, criId, userId);
        }

        sendAuditEventForProcessedVcResponse(
                vcs.isEmpty()
                        ? CriResourceRetrievedType.EMPTY.getType()
                        : CriResourceRetrievedType.VC.getType(),
                criId,
                auditEventUser);
    }

    private void sendAuditEventForProcessedVcResponse(
            String criResourceRetrievedType, String criId, AuditEventUser auditEventUser)
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
                        new AuditExtensionsCriResRetrieved(criId, criResourceRetrievedType)));
    }

    private AuditExtensionsVcEvidence getAuditExtensions(
            SignedJWT verifiableCredential, boolean isSuccessful)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var evidence = vc.getAsString(EVIDENCE);
        return new AuditExtensionsVcEvidence(jwtClaimsSet.getIssuer(), evidence, isSuccessful);
    }
}
