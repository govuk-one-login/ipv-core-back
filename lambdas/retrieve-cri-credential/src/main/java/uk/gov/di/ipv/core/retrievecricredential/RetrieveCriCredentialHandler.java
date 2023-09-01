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
import uk.gov.di.ipv.core.library.cimit.CiMitService;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.library.vchelper.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.library.verifiablecredential.exception.VerifiableCredentialResponseException;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.USE_POST_MITIGATIONS;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_CI_SCORING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NOT_FOUND_PATH;

public class RetrieveCriCredentialHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final String EVIDENCE = "evidence";
    private static final String JOURNEY = "journey";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Map<String, Object> JOURNEY_CI_SCORING =
            Map.of(JOURNEY, JOURNEY_CI_SCORING_PATH);
    private static final Map<String, Object> JOURNEY_ERROR = Map.of(JOURNEY, JOURNEY_ERROR_PATH);
    private static final Map<String, Object> JOURNEY_NOT_FOUND =
            Map.of(JOURNEY, JOURNEY_NOT_FOUND_PATH);
    private final VerifiableCredentialService verifiableCredentialService;
    private final IpvSessionService ipvSessionService;
    private final ConfigService configService;
    private final AuditService auditService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final CiMitService ciMitService;
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
            CiMitService ciMitService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            CriResponseService criResponseService) {
        this.verifiableCredentialService = verifiableCredentialService;
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.auditService = auditService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.ciMitService = ciMitService;
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
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator(configService);
        this.ciMitService = new CiMitService(configService);
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
        String criOAuthState = criOAuthSessionItem.getCriOAuthSessionId();
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
                processPendingResponse(
                        userId,
                        credentialIssuerId,
                        verifiableCredentialResponse,
                        criOAuthState,
                        ipvSessionItem);
            } else {
                processVerifiableCredentials(
                        userId,
                        credentialIssuerId,
                        credentialIssuerConfig,
                        ipAddress,
                        verifiableCredentialResponse.getVerifiableCredentials(),
                        clientOAuthSessionItem,
                        ipvSessionItem);
            }

            return JOURNEY_CI_SCORING;

        } catch (VerifiableCredentialException
                | VerifiableCredentialResponseException
                | CiPutException
                | CiPostMitigationsException e) {
            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, null, false, OAuth2Error.SERVER_ERROR_CODE);
            if (credentialIssuerId.equals(DCMAW_CRI)
                    && e instanceof VerifiableCredentialException vce
                    && vce.getHttpStatusCode() == HTTPResponse.SC_NOT_FOUND) {
                LogHelper.logErrorMessage(
                        "404 received from DCMAW CRI", vce.getErrorResponse().getMessage());
                return JOURNEY_NOT_FOUND;
            }
            return JOURNEY_ERROR;

        } catch (ParseException | JsonProcessingException | SqsException e) {
            LogHelper.logErrorMessage("Failed to send audit event to SQS queue.", e.getMessage());
            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, null, false, OAuth2Error.SERVER_ERROR_CODE);
            return JOURNEY_ERROR;
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LogHelper.logErrorMessage("Failed to parse access token.", e.getMessage());

            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, null, false, OAuth2Error.SERVER_ERROR_CODE);
            return JOURNEY_ERROR;
        }
    }

    private void processPendingResponse(
            String userId,
            String credentialIssuerId,
            VerifiableCredentialResponse verifiableCredentialResponse,
            String criOAuthState,
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
                criOAuthState,
                CriResponseService.STATUS_PENDING);
        // Update session to indicate no VC, but no error
        updateVisitedCredentials(ipvSessionItem, credentialIssuerId, null, false, null);
        // Audit
        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_LAMBDA_RESULT.getFieldName(),
                                "Successfully processed CRI pending response.")
                        .with(LOG_CRI_ID.getFieldName(), credentialIssuerId));
    }

    private void processVerifiableCredentials(
            String userId,
            String credentialIssuerId,
            CredentialIssuerConfig credentialIssuerConfig,
            String ipAddress,
            List<SignedJWT> verifiableCredentials,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws ParseException, SqsException, JsonProcessingException, CiPutException,
                    CiPostMitigationsException {
        final boolean postMitigatingVcs = configService.enabled(USE_POST_MITIGATIONS);
        final AuditEventUser auditEventUser =
                new AuditEventUser(
                        userId,
                        ipvSessionItem.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);

        final Set<String> excludedCredentialIssuers =
                UserIdentityService.getNonEvidenceCredentialIssuers(configService);
        final String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

        String issuer = null;
        for (SignedJWT vc : verifiableCredentials) {
            verifiableCredentialJwtValidator.validate(vc, credentialIssuerConfig, userId);

            boolean isSuccessful = VcHelper.isSuccessfulVc(vc, excludedCredentialIssuers);

            sendIpvVcReceivedAuditEvent(auditEventUser, vc, isSuccessful);

            submitVcToCiStorage(vc, govukSigninJourneyId, ipAddress);
            if (postMitigatingVcs) {
                postMitigatingVc(vc, govukSigninJourneyId, ipAddress);
            }

            verifiableCredentialService.persistUserCredentials(vc, credentialIssuerId, userId);

            issuer = vc.getJWTClaimsSet().getIssuer();
        }

        updateVisitedCredentials(ipvSessionItem, credentialIssuerId, issuer, true, null);

        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_LAMBDA_RESULT.getFieldName(),
                                "Successfully retrieved CRI credential.")
                        .with(LOG_CRI_ID.getFieldName(), credentialIssuerId));
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
        ciMitService.submitVC(vc, govukSigninJourneyId, ipAddress);
    }

    @Tracing
    private void postMitigatingVc(SignedJWT vc, String govukSigninJourneyId, String ipAddress)
            throws CiPostMitigationsException {
        ciMitService.submitMitigatingVcList(
                List.of(vc.serialize()), govukSigninJourneyId, ipAddress);
    }

    @Tracing
    private void updateVisitedCredentials(
            IpvSessionItem ipvSessionItem,
            String criId,
            String issuer,
            boolean returnedWithVc,
            String oauthError) {
        ipvSessionItem.addVisitedCredentialIssuerDetails(
                new VisitedCredentialIssuerDetailsDto(criId, issuer, returnedWithVc, oauthError));
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }
}
