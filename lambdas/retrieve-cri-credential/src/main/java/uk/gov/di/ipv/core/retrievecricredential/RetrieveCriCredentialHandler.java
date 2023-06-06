package uk.gov.di.ipv.core.retrievecricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.http.HttpStatus;
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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.vchelper.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.library.verifiablecredential.exception.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.verifiablecredential.exception.VerifiableCredentialResponseException;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validation.VerifiableCredentialJwtValidator;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;

public class RetrieveCriCredentialHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final String EVIDENCE = "evidence";
    private static final String JOURNEY = "journey";
    private static final Logger LOGGER = LogManager.getLogger();

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Map<String, Object> JOURNEY_NEXT = Map.of(JOURNEY, "/journey/next");
    private static final Map<String, Object> JOURNEY_ERROR = Map.of(JOURNEY, "/journey/error");
    private static final Map<String, Object> JOURNEY_PENDING = Map.of(JOURNEY, "/journey/pending");

    private final VerifiableCredentialService verifiableCredentialService;
    private final IpvSessionService ipvSessionService;
    private final ConfigService configService;
    private final AuditService auditService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final CiStorageService ciStorageService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final CriResponseService criResponseService;

    private String componentId;

    public RetrieveCriCredentialHandler(
            VerifiableCredentialService verifiableCredentialService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            AuditService auditService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            CiStorageService ciStorageService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            CriResponseService criResponseService) {
        this.verifiableCredentialService = verifiableCredentialService;
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.auditService = auditService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.ciStorageService = ciStorageService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.criResponseService = criResponseService;
    }

    @ExcludeFromGeneratedCoverageReport
    public RetrieveCriCredentialHandler() {
        this.configService = new ConfigService();
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator();
        this.ciStorageService = new CiStorageService(configService);
        this.criOAuthSessionService = new CriOAuthSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        LogHelper.attachComponentIdToLogs();

        String ipAddress = StepFunctionHelpers.getIpAddress(input);
        String featureSet = StepFunctionHelpers.getFeatureSet(input);
        configService.setFeatureSet(featureSet);

        IpvSessionItem ipvSessionItem;
        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        } catch (HttpResponseExceptionWithErrorBody e) {
            ErrorResponse errorResponse = e.getErrorResponse();
            LogHelper.logErrorMessage(
                    "Error in credential issuer return lambda.", errorResponse.getMessage());
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_BAD_REQUEST, errorResponse);
        }

        CriOAuthSessionItem criOAuthSessionItem =
                criOAuthSessionService.getCriOauthSessionItem(
                        ipvSessionItem.getCriOAuthSessionId());
        String credentialIssuerId = criOAuthSessionItem.getCriId();
        try {
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String userId = clientOAuthSessionItem.getUserId();

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            this.componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);

            CredentialIssuerConfig credentialIssuerConfig =
                    configService.getCredentialIssuerActiveConnectionConfig(credentialIssuerId);

            String apiKey =
                    credentialIssuerConfig.getRequiresApiKey()
                            ? configService.getCriPrivateApiKey(credentialIssuerId)
                            : null;

            VerifiableCredentialResponse verifiableCredentialResponse =
                    verifiableCredentialService.getVerifiableCredentialResponse(
                            BearerAccessToken.parse(criOAuthSessionItem.getAccessToken()),
                            credentialIssuerConfig,
                            apiKey,
                            credentialIssuerId);

            if (VerifiableCredentialStatus.PENDING.equals(
                    verifiableCredentialResponse.getCredentialStatus())) {
                return processPendingResponse(
                        userId,
                        credentialIssuerId,
                        verifiableCredentialResponse,
                        clientOAuthSessionItem,
                        ipvSessionItem);
            } else {
                return processVerifiableCredentials(
                        userId,
                        credentialIssuerId,
                        credentialIssuerConfig,
                        ipAddress,
                        verifiableCredentialResponse.getVerifiableCredentials(),
                        clientOAuthSessionItem,
                        ipvSessionItem);
            }

        } catch (VerifiableCredentialException
                | VerifiableCredentialResponseException
                | CiPutException e) {
            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);

            return JOURNEY_ERROR;
        } catch (ParseException | JsonProcessingException | SqsException e) {
            LogHelper.logErrorMessage("Failed to send audit event to SQS queue.", e.getMessage());
            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);
            return JOURNEY_ERROR;
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LogHelper.logErrorMessage("Failed to parse access token.", e.getMessage());

            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);

            return JOURNEY_ERROR;
        }
    }

    private Map<String, Object> processPendingResponse(
            String userId,
            String credentialIssuerId,
            VerifiableCredentialResponse verifiableCredentialResponse,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws JsonProcessingException {
        // Validate the response
        if (!userId.equals(verifiableCredentialResponse.getUserId())) {
            throw new VerifiableCredentialResponseException(
                    HTTPResponse.SC_SERVER_ERROR,
                    FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE);
        }
        // Create cri response item
        VerifiableCredentialResponseDto verifiableCredentialResponseDto =
                VerifiableCredentialResponseDto.builder()
                        .userId(userId)
                        .credentialStatus(
                                verifiableCredentialResponse.getCredentialStatus().getStatus())
                        .build();
        criResponseService.persistCriResponse(
                userId,
                credentialIssuerId,
                OBJECT_MAPPER.writeValueAsString(verifiableCredentialResponseDto),
                clientOAuthSessionItem.getState());
        // Update session to indicate no VC, but no error
        updateVisitedCredentials(ipvSessionItem, credentialIssuerId, false, null);
        // Audit
        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_LAMBDA_RESULT.getFieldName(),
                                "Successfully processed CRI pending response.")
                        .with(LOG_CRI_ID.getFieldName(), credentialIssuerId));
        return JOURNEY_PENDING;
    }

    private Map<String, Object> processVerifiableCredentials(
            String userId,
            String credentialIssuerId,
            CredentialIssuerConfig credentialIssuerConfig,
            String ipAddress,
            List<SignedJWT> verifiableCredentials,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws ParseException, SqsException, JsonProcessingException, CiPutException {
        final AuditEventUser auditEventUser =
                new AuditEventUser(
                        userId,
                        ipvSessionItem.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);

        final List<CredentialIssuerConfig> excludedCriConfigs =
                List.of(
                        configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI),
                        configService.getCredentialIssuerActiveConnectionConfig(
                                CLAIMED_IDENTITY_CRI));

        for (SignedJWT vc : verifiableCredentials) {
            verifiableCredentialJwtValidator.validate(vc, credentialIssuerConfig, userId);

            boolean isSuccessful = VcHelper.isSuccessfulVc(vc, excludedCriConfigs);

            sendIpvVcReceivedAuditEvent(auditEventUser, vc, isSuccessful);

            submitVcToCiStorage(vc, clientOAuthSessionItem.getGovukSigninJourneyId(), ipAddress);

            verifiableCredentialService.persistUserCredentials(vc, credentialIssuerId, userId);
        }

        updateVisitedCredentials(ipvSessionItem, credentialIssuerId, true, null);

        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_LAMBDA_RESULT.getFieldName(),
                                "Successfully retrieved CRI credential.")
                        .with(LOG_CRI_ID.getFieldName(), credentialIssuerId));

        return JOURNEY_NEXT;
    }

    @Tracing
    private void sendIpvVcReceivedAuditEvent(
            AuditEventUser auditEventUser, SignedJWT verifiableCredential, boolean isSuccessful)
            throws ParseException, JsonProcessingException, SqsException {
        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_VC_RECEIVED,
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

    @Tracing
    private void updateVisitedCredentials(
            IpvSessionItem ipvSessionItem,
            String criId,
            boolean returnedWithVc,
            String oauthError) {
        ipvSessionItem.addVisitedCredentialIssuerDetails(
                new VisitedCredentialIssuerDetailsDto(criId, returnedWithVc, oauthError));
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }
}
