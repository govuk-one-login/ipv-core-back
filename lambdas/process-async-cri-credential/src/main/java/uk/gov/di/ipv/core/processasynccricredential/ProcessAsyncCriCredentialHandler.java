package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processasynccricredential.domain.BaseAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.ErrorAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.exceptions.AsyncVerifiableCredentialException;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForF2F;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_ASYNC_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.getAsyncResponseMessage;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.isSuccessAsyncCriResponse;

public class ProcessAsyncCriCredentialHandler
        implements RequestHandler<SQSEvent, SQSBatchResponse> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final VerifiableCredentialValidator verifiableCredentialValidator;
    private final AuditService auditService;
    private final CimitService cimitService;
    private final CriResponseService criResponseService;
    private final EvcsService evcsService;

    public ProcessAsyncCriCredentialHandler(
            ConfigService configService,
            VerifiableCredentialService verifiableCredentialService,
            VerifiableCredentialValidator verifiableCredentialValidator,
            AuditService auditService,
            CimitService cimitService,
            CriResponseService criResponseService,
            EvcsService evcsService) {
        this.configService = configService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
        this.verifiableCredentialService = verifiableCredentialService;
        this.auditService = auditService;
        this.cimitService = cimitService;
        this.criResponseService = criResponseService;
        this.evcsService = evcsService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessAsyncCriCredentialHandler() {
        this.configService = ConfigService.create();
        this.verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = AuditService.create(configService);
        this.cimitService = new CimitService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.evcsService = new EvcsService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {
        try {
            LogHelper.attachComponentId(configService);
            List<SQSBatchResponse.BatchItemFailure> failedRecords = new ArrayList<>();

            for (SQSMessage message : event.getRecords()) {
                failedRecords.addAll(processOrReturnItemFailure(message));
            }

            return SQSBatchResponse.builder().withBatchItemFailures(failedRecords).build();
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private List<SQSBatchResponse.BatchItemFailure> processOrReturnItemFailure(SQSMessage message) {
        try {
            final BaseAsyncCriResponse asyncCriResponse =
                    getAsyncResponseMessage(message.getBody());
            if (isSuccessAsyncCriResponse(asyncCriResponse)) {
                processSuccessAsyncCriResponse((SuccessAsyncCriResponse) asyncCriResponse);
            } else {
                processErrorAsyncCriResponse((ErrorAsyncCriResponse) asyncCriResponse);
            }
        } catch (JsonProcessingException
                | ParseException
                | CiPutException
                | AsyncVerifiableCredentialException
                | UnrecognisedVotException
                | CiPostMitigationsException
                | CredentialParseException
                | EvcsServiceException
                | HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to process VC response message.", e));
            return List.of(new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
        } catch (VerifiableCredentialException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Failed to process VC response message.")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getErrorResponse()));
            return List.of(new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
        }
        return List.of();
    }

    private void processErrorAsyncCriResponse(ErrorAsyncCriResponse errorAsyncCriResponse) {
        var userId = errorAsyncCriResponse.getUserId();
        var state = errorAsyncCriResponse.getOauthState();
        Optional<CriResponseItem> criResponseItem = getCriResponseItem(userId, state);

        criResponseItem.ifPresent(
                responseItem -> {
                    responseItem.setStatus(CriResponseService.STATUS_ERROR);
                    criResponseService.updateCriResponseItem(responseItem);
                });

        LOGGER.error(
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "Error response received from Credential Issuer")
                        .with(
                                LOG_ERROR_DESCRIPTION.getFieldName(),
                                errorAsyncCriResponse.getErrorDescription())
                        .with(LOG_ERROR_CODE.getFieldName(), errorAsyncCriResponse.getError()));

        criResponseItem.ifPresent(
                responseItem ->
                        sendIpvVcErrorAuditEvent(
                                errorAsyncCriResponse,
                                Cri.fromId(responseItem.getCredentialIssuer())));
    }

    private void processSuccessAsyncCriResponse(SuccessAsyncCriResponse successAsyncCriResponse)
            throws ParseException, CiPutException, AsyncVerifiableCredentialException,
                    CiPostMitigationsException, VerifiableCredentialException,
                    UnrecognisedVotException, CredentialParseException, EvcsServiceException,
                    HttpResponseExceptionWithErrorBody {
        var userId = successAsyncCriResponse.getUserId();
        var state = successAsyncCriResponse.getOauthState();
        Optional<CriResponseItem> criResponseItem = getCriResponseItem(userId, state);

        if (criResponseItem.isEmpty()) {
            LOGGER.error(
                    LogHelper.buildLogMessage("No response item found given user id and state"));
            throw new AsyncVerifiableCredentialException(UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL);
        }

        var cri = Cri.fromId(criResponseItem.get().getCredentialIssuer());

        configService.setFeatureSet(criResponseItem.get().getFeatureSet());

        var oauthCriConfig = configService.getOauthCriActiveConnectionConfig(cri);

        var vcs =
                verifiableCredentialValidator.parseAndValidate(
                        userId,
                        cri,
                        successAsyncCriResponse.getVerifiableCredentialJWTs(),
                        oauthCriConfig.getSigningKey(),
                        oauthCriConfig.getComponentId());

        for (var vc : vcs) {
            boolean isSuccessful = VcHelper.isSuccessfulVc(vc);

            AuditEventUser auditEventUser = new AuditEventUser(userId, null, null, null);
            sendIpvVcReceivedAuditEvent(auditEventUser, vc, cri, isSuccessful);

            submitVcToCiStorage(vc);
            postMitigatingVc(vc);

            if (configService.enabled(EVCS_ASYNC_WRITE_ENABLED)) {
                try {
                    evcsService.storePendingVc(vc);
                    vc.setMigrated(Instant.now());
                } catch (EvcsServiceException e) {
                    if (configService.enabled(EVCS_READ_ENABLED)) {
                        throw e;
                    } else {
                        LOGGER.error(
                                LogHelper.buildErrorMessage("Failed to store EVCS async VC", e));
                    }
                }
            }
            verifiableCredentialService.persistUserCredentials(vc);

            sendIpvVcConsumedAuditEvent(auditEventUser, vc, cri);
        }
    }

    private Optional<CriResponseItem> getCriResponseItem(String userId, String state) {
        final List<CriResponseItem> criResponseItems =
                criResponseService.getCriResponseItemsByUserId(userId);
        return criResponseItems.stream()
                .filter(item -> Objects.equals(item.getOauthState(), state))
                .findFirst();
    }

    private void sendIpvVcReceivedAuditEvent(
            AuditEventUser auditEventUser,
            VerifiableCredential verifiableCredential,
            Cri cri,
            boolean isSuccessful)
            throws UnrecognisedVotException {
        if (Cri.F2F.equals(cri)) {
            AuditEvent auditEvent =
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            getExtensionsForAudit(verifiableCredential, isSuccessful));
            auditService.sendAuditEvent(auditEvent);
        }
    }

    void sendIpvVcConsumedAuditEvent(
            AuditEventUser auditEventUser, VerifiableCredential vc, Cri cri) {
        if (Cri.F2F.equals(cri)) {
            AuditEvent auditEvent =
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_F2F_CRI_VC_CONSUMED,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            null,
                            getRestrictedAuditDataForF2F(vc));
            auditService.sendAuditEvent(auditEvent);
        }
    }

    private void sendIpvVcErrorAuditEvent(ErrorAsyncCriResponse errorAsyncCriResponse, Cri cri) {
        if (Cri.F2F.equals(cri)) {
            AuditEventUser auditEventUser =
                    new AuditEventUser(errorAsyncCriResponse.getUserId(), null, null, null);

            AuditExtensionErrorParams extensionErrorParams =
                    new AuditExtensionErrorParams.Builder()
                            .setErrorCode(errorAsyncCriResponse.getError())
                            .setErrorDescription(errorAsyncCriResponse.getErrorDescription())
                            .build();

            AuditEvent auditEvent =
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_F2F_CRI_VC_ERROR,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            extensionErrorParams);
            LOGGER.info(
                    LogHelper.buildLogMessage("Sending audit event IPV_F2F_CRI_VC_ERROR message."));
            auditService.sendAuditEvent(auditEvent);
        }
    }

    private void submitVcToCiStorage(VerifiableCredential vc) throws CiPutException {
        cimitService.submitVC(vc, null, null);
    }

    private void postMitigatingVc(VerifiableCredential vc) throws CiPostMitigationsException {
        cimitService.submitMitigatingVcList(List.of(vc), null, null);
    }
}
