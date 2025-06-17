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
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.tracing.InstrumentationHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processasynccricredential.domain.ErrorAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.exceptions.AsyncVerifiableCredentialException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAuditWithCriId;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForAsync;
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
    private final VerifiableCredentialValidator verifiableCredentialValidator;
    private final AuditService auditService;
    private final CimitService cimitService;
    private final CriResponseService criResponseService;
    private final EvcsService evcsService;

    public ProcessAsyncCriCredentialHandler(
            ConfigService configService,
            VerifiableCredentialValidator verifiableCredentialValidator,
            AuditService auditService,
            CimitService cimitService,
            CriResponseService criResponseService,
            EvcsService evcsService) {
        this.configService = configService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
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
        this.auditService = AuditService.create(configService);
        this.cimitService = new CimitService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.evcsService = new EvcsService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {
        try {
            LogHelper.attachTraceId();
            LogHelper.attachComponentId(configService);
            String queueName = extractQueueName(event);
            LogHelper.attachQueueNameToLogs(queueName);
            InstrumentationHelper.setSpanAttribute("sqs.queue.name", queueName);

            var failedRecords = new ArrayList<SQSBatchResponse.BatchItemFailure>();

            for (var sqsMessage : event.getRecords()) {
                failedRecords.addAll(processOrReturnItemFailure(sqsMessage));
            }

            return SQSBatchResponse.builder().withBatchItemFailures(failedRecords).build();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private List<SQSBatchResponse.BatchItemFailure> processOrReturnItemFailure(SQSMessage message) {
        try {
            final var asyncCriResponse = getAsyncResponseMessage(message.getBody());
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
            if (e instanceof AsyncVerifiableCredentialException asyncVcException
                    && asyncVcException
                            .getErrorResponse()
                            .equals(UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL)) {
                EmbeddedMetricHelper.asyncCriResponseUnexpected(extractQueueName(message));
            }
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
        Optional<CriResponseItem> criResponseItem =
                criResponseService.getCriResponseItemWithState(userId, state);

        criResponseItem.ifPresent(
                responseItem -> {
                    Cri cri = Cri.fromId(responseItem.getCredentialIssuer());
                    String errorCode = errorAsyncCriResponse.getError();
                    EmbeddedMetricHelper.asyncCriErrorResponse(cri.getId(), errorCode);
                    if (CriResponseService.ERROR_ACCESS_DENIED.equals(errorCode)) {
                        responseItem.setStatus(CriResponseService.STATUS_ABANDON);
                    } else {
                        responseItem.setStatus(CriResponseService.STATUS_ERROR);
                    }
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

        var criResponseItem = criResponseService.getCriResponseItemWithState(userId, state);
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
            var auditEventUser = new AuditEventUser(userId, null, null, null);
            sendIpvVcReceivedAuditEvent(auditEventUser, vc, cri, VcHelper.isSuccessfulVc(vc));

            submitVcToCiStorage(vc);
            postMitigatingVc(vc);
            evcsService.storePendingVc(vc);
            sendIpvVcConsumedAuditEvent(auditEventUser, vc, cri, VcHelper.isSuccessfulVc(vc));
        }
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
        AuditEvent genericAuditEvent =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_ASYNC_CRI_VC_RECEIVED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        getExtensionsForAuditWithCriId(verifiableCredential, isSuccessful));
        auditService.sendAuditEvent(genericAuditEvent);
    }

    void sendIpvVcConsumedAuditEvent(
            AuditEventUser auditEventUser,
            VerifiableCredential verifiableCredential,
            Cri cri,
            boolean isSuccessful)
            throws UnrecognisedVotException {
        if (Cri.F2F.equals(cri)) {
            AuditEvent auditEvent =
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_F2F_CRI_VC_CONSUMED,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            null,
                            getRestrictedAuditDataForAsync(verifiableCredential));
            auditService.sendAuditEvent(auditEvent);
        }

        AuditEvent auditEvent =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_ASYNC_CRI_VC_CONSUMED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        getExtensionsForAuditWithCriId(verifiableCredential, isSuccessful),
                        getRestrictedAuditDataForAsync(verifiableCredential));
        auditService.sendAuditEvent(auditEvent);
    }

    private void sendIpvVcErrorAuditEvent(ErrorAsyncCriResponse errorAsyncCriResponse, Cri cri) {
        AuditEventUser auditEventUser =
                new AuditEventUser(errorAsyncCriResponse.getUserId(), null, null, null);
        if (Cri.F2F.equals(cri)) {
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

        AuditExtensionErrorParams extensionErrorParams =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(errorAsyncCriResponse.getError())
                        .setErrorDescription(errorAsyncCriResponse.getErrorDescription())
                        .setCredentialIssuerId(cri.getId())
                        .build();

        AuditEvent auditEvent =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_ASYNC_CRI_VC_ERROR,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        extensionErrorParams);
        LOGGER.info(
                LogHelper.buildLogMessage("Sending audit event IPV_ASYNC_CRI_VC_ERROR message."));
        auditService.sendAuditEvent(auditEvent);
    }

    private void submitVcToCiStorage(VerifiableCredential vc) throws CiPutException {
        cimitService.submitVC(vc, null, null);
    }

    private void postMitigatingVc(VerifiableCredential vc) throws CiPostMitigationsException {
        cimitService.submitMitigatingVcList(List.of(vc), null, null);
    }

    private String extractQueueName(SQSEvent event) {
        var records = event.getRecords();
        if (!isNullOrEmpty(records)) {
            SQSMessage firstMessage =
                    records.get(0); // Batched messages should all come from same queue
            return extractQueueName(firstMessage);
        }
        return "unknown";
    }

    private String extractQueueName(SQSMessage message) {
        try {
            if (message != null) {
                String arn = message.getEventSourceArn();
                return arn.substring(arn.lastIndexOf(":") + 1);
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to extract queue name from SQS message", e);
        }
        return "unknown";
    }
}
