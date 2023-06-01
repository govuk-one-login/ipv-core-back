package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;
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
import uk.gov.di.ipv.core.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.vchelper.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validation.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessage;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class ProcessAsyncCriCredentialHandler
        implements RequestHandler<SQSEvent, SQSBatchResponse> {
    private static final String EVIDENCE = "evidence";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String DEFAULT_CREDENTIAL_ISSUER = "f2f";
    private static final ObjectMapper mapper = new ObjectMapper();
    private final ConfigService configService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final AuditService auditService;
    private final CiStorageService ciStorageService;
    private final String componentId;

    public ProcessAsyncCriCredentialHandler(
            ConfigService configService,
            VerifiableCredentialService verifiableCredentialService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            AuditService auditService,
            CiStorageService ciStorageService) {
        this.configService = configService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.verifiableCredentialService = verifiableCredentialService;
        this.auditService = auditService;
        this.componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
        this.ciStorageService = ciStorageService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessAsyncCriCredentialHandler() {
        this.configService = new ConfigService();
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator();
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.ciStorageService = new CiStorageService(configService);
        this.componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {

        List<SQSBatchResponse.BatchItemFailure> failedRecords = new ArrayList<>();
        for (SQSMessage message : event.getRecords()) {
            try {
                processMessage(message);
            } catch (JsonProcessingException | ParseException | SqsException | CiPutException e) {
                LogHelper.logErrorMessage("Failed to process VC response message.", e.getMessage());
                failedRecords.add(new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            }
        }
        return SQSBatchResponse.builder().withBatchItemFailures(failedRecords).build();
    }

    public void processMessage(SQSMessage message)
            throws JsonProcessingException, ParseException, SqsException, CiPutException {
        final CriResponseMessage criResponseMessage =
                mapper.readerFor(CriResponseMessage.class).readValue(message.getBody());
        if (criResponseMessage.getError() == null) {
            final List<SignedJWT> verifiableCredentials = new ArrayList<>();
            for (String verifiableCredentialString :
                    criResponseMessage.getVerifiableCredentialJWTs()) {
                verifiableCredentials.add(SignedJWT.parse(verifiableCredentialString));
            }
            final String userId = criResponseMessage.getUserId();
            String credentialIssuerId = criResponseMessage.getCredentialIssuer();
            if (credentialIssuerId == null) {
                credentialIssuerId = DEFAULT_CREDENTIAL_ISSUER;
            }
            CredentialIssuerConfig credentialIssuerConfig =
                    configService.getCredentialIssuerActiveConnectionConfig(credentialIssuerId);
            for (SignedJWT vc : verifiableCredentials) {
                verifiableCredentialJwtValidator.validate(vc, credentialIssuerConfig, userId);
                CredentialIssuerConfig addressCriConfig =
                        configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI);
                boolean isSuccessful = VcHelper.isSuccessfulVc(vc, addressCriConfig);

                // TODO: Can we get signin journey id?
                // TODO: What to do for the ip address?
                AuditEventUser auditEventUser = new AuditEventUser(userId, null, null, null);

                sendIpvVcReceivedAuditEvent(auditEventUser, vc, isSuccessful);

                submitVcToCiStorage(vc, "TBD", null);

                verifiableCredentialService.persistUserCredentials(vc, credentialIssuerId, userId);

                // TODO: Audit IPV_ASYNC_CRI_MESSAGE_CONSUMED
            }
        } else {
            LOGGER.error(
                    new StringMapMessage()
                            .with("error", criResponseMessage.getError())
                            .with("errorDescription", criResponseMessage.getErrorDescription()));
        }
    }

    @Tracing
    private void sendIpvVcReceivedAuditEvent(
            AuditEventUser auditEventUser, SignedJWT verifiableCredential, boolean isSuccessful)
            throws ParseException, JsonProcessingException, SqsException {
        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_ASYNC_VC_RECEIVED,
                        componentId,
                        auditEventUser,
                        getAuditExtensions(verifiableCredential, isSuccessful));
        auditService.sendAuditEvent(auditEvent);
    }

    private AuditExtensionsVcEvidence getAuditExtensions(
            SignedJWT verifiableCredential, boolean isSuccessful)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var evidence = vc.getAsString(EVIDENCE);
        return new AuditExtensionsVcEvidence(jwtClaimsSet.getIssuer(), evidence, isSuccessful);
    }

    @Tracing
    private void submitVcToCiStorage(SignedJWT vc, String govukSigninJourneyId, String ipAddress)
            throws CiPutException {
        ciStorageService.submitVC(vc, govukSigninJourneyId, ipAddress);
    }
}
