package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processasynccricredential.domain.BaseAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.ErrorAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.exceptions.AsyncVerifiableCredentialException;
import uk.gov.di.ipv.core.processasynccricredential.helpers.JwtParser;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.getAsyncResponseMessage;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.isSuccessAsyncCriResponse;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AuditCriResponseHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AuditCriResponseHelper.getRestrictedDataForAuditEvent;

public class ProcessAsyncCriCredentialHandler
        implements RequestHandler<SQSEvent, SQSBatchResponse> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final AuditService auditService;
    private final CiMitService ciMitService;
    private final JwtParser jwtParser;
    private final CriResponseService criResponseService;

    public ProcessAsyncCriCredentialHandler(
            ConfigService configService,
            VerifiableCredentialService verifiableCredentialService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            AuditService auditService,
            CiMitService ciMitService,
            CriResponseService criResponseService) {
        this.configService = configService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.verifiableCredentialService = verifiableCredentialService;
        this.auditService = auditService;
        this.ciMitService = ciMitService;
        this.jwtParser = new JwtParser();
        this.criResponseService = criResponseService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessAsyncCriCredentialHandler() {
        this.configService = new ConfigService();
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.ciMitService = new CiMitService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.jwtParser = new JwtParser();
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
        List<SQSBatchResponse.BatchItemFailure> failedRecords = new ArrayList<>();

        for (SQSMessage message : event.getRecords()) {

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
                    | SqsException
                    | CiPutException
                    | AsyncVerifiableCredentialException
                    | CiPostMitigationsException e) {
                LOGGER.error(
                        LogHelper.buildErrorMessage("Failed to process VC response message.", e));
                failedRecords.add(new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            } catch (VerifiableCredentialException e) {
                LOGGER.error(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Failed to process VC response message.")
                                .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getErrorResponse()));
                failedRecords.add(new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            }
        }

        return SQSBatchResponse.builder().withBatchItemFailures(failedRecords).build();
    }

    private void processErrorAsyncCriResponse(ErrorAsyncCriResponse errorAsyncCriResponse)
            throws SqsException {
        CriResponseItem responseItem =
                criResponseService.getCriResponseItem(
                        errorAsyncCriResponse.getUserId(),
                        errorAsyncCriResponse.getCredentialIssuer());

        if (responseItem != null) {
            responseItem.setStatus(CriResponseService.STATUS_ERROR);
            criResponseService.updateCriResponseItem(responseItem);
        }

        LOGGER.error(
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "Error response received from Credential Issuer")
                        .with(
                                LOG_ERROR_DESCRIPTION.getFieldName(),
                                errorAsyncCriResponse.getErrorDescription())
                        .with(LOG_ERROR_CODE.getFieldName(), errorAsyncCriResponse.getError())
                        .with(
                                LOG_CRI_ISSUER.getFieldName(),
                                errorAsyncCriResponse.getCredentialIssuer()));

        sendIpvVcErrorAuditEvent(errorAsyncCriResponse);
    }

    @Tracing
    private void processSuccessAsyncCriResponse(SuccessAsyncCriResponse successAsyncCriResponse)
            throws ParseException, SqsException, JsonProcessingException, CiPutException,
                    AsyncVerifiableCredentialException, CiPostMitigationsException,
                    VerifiableCredentialException {

        validateOAuthState(successAsyncCriResponse);

        final List<SignedJWT> verifiableCredentials =
                jwtParser.parseVerifiableCredentialJWTs(
                        successAsyncCriResponse.getVerifiableCredentialJWTs());

        final OauthCriConfig oauthCriConfig =
                configService.getOauthCriActiveConnectionConfig(
                        successAsyncCriResponse.getCredentialIssuer());

        for (SignedJWT verifiableCredential : verifiableCredentials) {
            verifiableCredentialJwtValidator.validate(
                    verifiableCredential, oauthCriConfig, successAsyncCriResponse.getUserId());

            boolean isSuccessful = VcHelper.isSuccessfulVc(verifiableCredential);

            AuditEventUser auditEventUser =
                    new AuditEventUser(successAsyncCriResponse.getUserId(), null, null, null);
            sendIpvVcReceivedAuditEvent(auditEventUser, verifiableCredential, isSuccessful);

            submitVcToCiStorage(verifiableCredential);
            postMitigatingVc(verifiableCredential);

            verifiableCredentialService.persistUserCredentials(
                    verifiableCredential,
                    successAsyncCriResponse.getCredentialIssuer(),
                    successAsyncCriResponse.getUserId());

            sendIpvVcConsumedAuditEvent(auditEventUser, verifiableCredential);
        }
    }

    private void validateOAuthState(SuccessAsyncCriResponse successAsyncCriResponse)
            throws AsyncVerifiableCredentialException {
        final CriResponseItem criResponseItem =
                criResponseService.getCriResponseItem(
                        successAsyncCriResponse.getUserId(),
                        successAsyncCriResponse.getCredentialIssuer());
        if (criResponseItem == null) {
            LOGGER.error(LogHelper.buildLogMessage("No response item found"));
            throw new AsyncVerifiableCredentialException(UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL);
        }
        if (criResponseItem.getOauthState() == null
                || !criResponseItem
                        .getOauthState()
                        .equals(successAsyncCriResponse.getOauthState())) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            "State mismatch between response item and async response message"));
            throw new AsyncVerifiableCredentialException(UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL);
        }
    }

    @Tracing
    private void sendIpvVcReceivedAuditEvent(
            AuditEventUser auditEventUser, SignedJWT verifiableCredential, boolean isSuccessful)
            throws ParseException, JsonProcessingException, SqsException {
        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        getExtensionsForAudit(verifiableCredential, isSuccessful, F2F_CRI));
        auditService.sendAuditEvent(auditEvent);
    }

    @Tracing
    void sendIpvVcConsumedAuditEvent(AuditEventUser auditEventUser, SignedJWT verifiableCredential)
            throws ParseException, SqsException {
        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_CRI_VC_CONSUMED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        null,
                        getRestrictedDataForAuditEvent(verifiableCredential));
        auditService.sendAuditEvent(auditEvent);
    }

    @Tracing
    private void sendIpvVcErrorAuditEvent(ErrorAsyncCriResponse errorAsyncCriResponse)
            throws SqsException {
        AuditEventUser auditEventUser =
                new AuditEventUser(errorAsyncCriResponse.getUserId(), null, null, null);

        AuditExtensionErrorParams extensionErrorParams =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(errorAsyncCriResponse.getError())
                        .setErrorDescription(errorAsyncCriResponse.getErrorDescription())
                        .build();

        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_CRI_VC_ERROR,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        extensionErrorParams);
        LOGGER.info(LogHelper.buildLogMessage("Sending audit event IPV_F2F_CRI_VC_ERROR message."));
        auditService.sendAuditEvent(auditEvent);
    }

    @Tracing
    private void submitVcToCiStorage(SignedJWT vc) throws CiPutException {
        ciMitService.submitVC(vc, null, null);
    }

    @Tracing
    private void postMitigatingVc(SignedJWT vc) throws CiPostMitigationsException {
        ciMitService.submitMitigatingVcList(List.of(vc.serialize()), null, null);
    }
}
