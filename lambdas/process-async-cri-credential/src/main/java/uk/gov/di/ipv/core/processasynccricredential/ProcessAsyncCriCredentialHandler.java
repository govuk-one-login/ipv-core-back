package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONArray;
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
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.vchelper.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validation.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processasynccricredential.auditing.AuditRestrictedVcNameParts;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessage;
import uk.gov.di.ipv.core.processasynccricredential.exceptions.AsyncVerifiableCredentialException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class ProcessAsyncCriCredentialHandler
        implements RequestHandler<SQSEvent, SQSBatchResponse> {
    private static final String EVIDENCE = "evidence";
    private static final String VC_CREDENTIAL_SUBJECT = "credentialSubject";
    private static final String VC_NAME = "name";
    private static final String VC_NAME_PARTS = "nameParts";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String DEFAULT_CREDENTIAL_ISSUER = "f2f";
    private static final ObjectMapper mapper = new ObjectMapper();
    private final ConfigService configService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final AuditService auditService;
    private final CiStorageService ciStorageService;

    private final CriResponseService criResponseService;
    private final String componentId;

    public ProcessAsyncCriCredentialHandler(
            ConfigService configService,
            VerifiableCredentialService verifiableCredentialService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            AuditService auditService,
            CiStorageService ciStorageService,
            CriResponseService criResponseService) {
        this.configService = configService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.verifiableCredentialService = verifiableCredentialService;
        this.auditService = auditService;
        this.componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
        this.ciStorageService = ciStorageService;
        this.criResponseService = criResponseService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessAsyncCriCredentialHandler() {
        this.configService = new ConfigService();
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator();
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.ciStorageService = new CiStorageService(configService);
        this.criResponseService = new CriResponseService(configService);
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
            } catch (JsonProcessingException
                    | ParseException
                    | SqsException
                    | CiPutException
                    | AsyncVerifiableCredentialException e) {
                LogHelper.logErrorMessage("Failed to process VC response message.", e.getMessage());
                failedRecords.add(new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            }
        }
        return SQSBatchResponse.builder().withBatchItemFailures(failedRecords).build();
    }

    public void processMessage(SQSMessage message)
            throws JsonProcessingException, ParseException, SqsException, CiPutException,
                    AsyncVerifiableCredentialException {
        final CriResponseMessage criResponseMessage =
                mapper.readerFor(CriResponseMessage.class).readValue(message.getBody());
        if (criResponseMessage.getError() == null) {
            String credentialIssuerId = criResponseMessage.getCredentialIssuer();
            if (credentialIssuerId == null) {
                credentialIssuerId = DEFAULT_CREDENTIAL_ISSUER;
            }
            final String userId = criResponseMessage.getUserId();
            // Get the CRI response, if we can't find it, we're not expecting the VC and we throw an
            // error
            final CriResponseItem criResponseItem =
                    criResponseService.getCriResponseItem(userId, credentialIssuerId);
            if (criResponseItem == null) {
                LOGGER.error(
                        new StringMapMessage().with("errorDescription", "No response item found"));
                throw new AsyncVerifiableCredentialException(
                        UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL);
            }
            // oauthState should match between the initial F2F session and the async response
            if (!criResponseItem.getOauthState().equals(criResponseMessage.getOauthState())) {
                LOGGER.error(
                        new StringMapMessage()
                                .with(
                                        "errorDescription",
                                        "State mismatch between response item and async response message"));
                throw new AsyncVerifiableCredentialException(
                        UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL);
            }
            final List<SignedJWT> verifiableCredentials = new ArrayList<>();
            for (String verifiableCredentialString :
                    criResponseMessage.getVerifiableCredentialJWTs()) {
                verifiableCredentials.add(SignedJWT.parse(verifiableCredentialString));
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

                submitVcToCiStorage(vc, null, null);

                verifiableCredentialService.persistUserCredentials(vc, credentialIssuerId, userId);

                sendIpvVcConsumedAuditEvent(auditEventUser, vc);
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
                        AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED,
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

    private AuditRestrictedVcNameParts getVcNamePartsForAudit(SignedJWT verifiableCredential)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);
        var name = (JSONArray) credentialSubject.get(VC_NAME);
        var nameParts = ((JSONObject) name.get(0)).getAsString(VC_NAME_PARTS);
        return new AuditRestrictedVcNameParts(mapper.readTree(nameParts));
    }

    @Tracing
    private void sendIpvVcConsumedAuditEvent(
            AuditEventUser auditEventUser, SignedJWT verifiableCredential)
            throws ParseException, JsonProcessingException, SqsException {
        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_CRI_VC_CONSUMED,
                        componentId,
                        auditEventUser,
                        null,
                        getVcNamePartsForAudit(verifiableCredential));
        auditService.sendAuditEvent(auditEvent);
    }
}
