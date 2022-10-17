package uk.gov.di.ipv.core.retrievecricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.KmsEs256Signer;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.JOURNEY;

public class RetrieveCriCredentialHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    public static final String EVIDENCE = "evidence";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> JOURNEY_NEXT = Map.of(JOURNEY, "/journey/next");
    private static final Map<String, Object> JOURNEY_ERROR = Map.of(JOURNEY, "/journey/error");

    private final CredentialIssuerService credentialIssuerService;
    private final IpvSessionService ipvSessionService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final CiStorageService ciStorageService;

    private String componentId;

    public RetrieveCriCredentialHandler(
            CredentialIssuerService credentialIssuerService,
            IpvSessionService ipvSessionService,
            ConfigurationService configurationService,
            AuditService auditService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            CiStorageService ciStorageService) {
        this.credentialIssuerService = credentialIssuerService;
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
        this.auditService = auditService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.ciStorageService = ciStorageService;
    }

    @ExcludeFromGeneratedCoverageReport
    public RetrieveCriCredentialHandler() {
        this.configurationService = new ConfigurationService();
        this.credentialIssuerService =
                new CredentialIssuerService(
                        configurationService,
                        new KmsEs256Signer(configurationService.getSigningKeyId()));
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator();
        this.ciStorageService = new CiStorageService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        LogHelper.attachComponentIdToLogs();

        IpvSessionItem ipvSessionItem;
        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        } catch (HttpResponseExceptionWithErrorBody e) {
            ErrorResponse errorResponse = e.getErrorResponse();
            LOGGER.error(
                    "Error in credential issuer return lambda because: {}",
                    errorResponse.getMessage());
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_BAD_REQUEST, errorResponse);
        }

        String credentialIssuerId = ipvSessionItem.getCredentialIssuerSessionDetails().getCriId();
        try {
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            String userId = clientSessionDetailsDto.getUserId();

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientSessionDetailsDto.getGovukSigninJourneyId());

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            userId,
                            ipvSessionItem.getIpvSessionId(),
                            clientSessionDetailsDto.getGovukSigninJourneyId());
            this.componentId =
                    configurationService.getSsmParameter(
                            ConfigurationVariable.AUDIENCE_FOR_CLIENTS);

            CredentialIssuerConfig credentialIssuerConfig =
                    configurationService.getCredentialIssuer(credentialIssuerId);

            String apiKey =
                    configurationService.getCriPrivateApiKey(credentialIssuerConfig.getId());

            List<SignedJWT> verifiableCredentials =
                    credentialIssuerService.getVerifiableCredential(
                            BearerAccessToken.parse(
                                    ipvSessionItem
                                            .getCredentialIssuerSessionDetails()
                                            .getAccessToken()),
                            credentialIssuerConfig,
                            apiKey);

            for (SignedJWT vc : verifiableCredentials) {
                verifiableCredentialJwtValidator.validate(vc, credentialIssuerConfig, userId);

                sendIpvVcReceivedAuditEvent(auditEventUser, vc);

                submitVcToCiStorage(vc, clientSessionDetailsDto.getGovukSigninJourneyId());

                credentialIssuerService.persistUserCredentials(vc, credentialIssuerId, userId);
            }

            updateVisitedCredentials(ipvSessionItem, credentialIssuerId, true, null);

            var message =
                    new MapMessage()
                            .with("lambdaResult", "Successfully retrieved CRI credential.")
                            .with("criId", credentialIssuerId);
            LOGGER.info(message);

            return JOURNEY_NEXT;
        } catch (CredentialIssuerException | CiPutException e) {
            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);

            return JOURNEY_ERROR;
        } catch (ParseException | JsonProcessingException | SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());

            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);
            return JOURNEY_ERROR;
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOGGER.error("Failed to parse access token: {}", e.getMessage());

            updateVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);

            return JOURNEY_ERROR;
        }
    }

    @Tracing
    private void sendIpvVcReceivedAuditEvent(
            AuditEventUser auditEventUser, SignedJWT verifiableCredential)
            throws ParseException, JsonProcessingException, SqsException {
        AuditEvent auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_VC_RECEIVED,
                        componentId,
                        auditEventUser,
                        getAuditExtensions(verifiableCredential));
        auditService.sendAuditEvent(auditEvent);
    }

    private AuditExtensionsVcEvidence getAuditExtensions(SignedJWT verifiableCredential)
            throws ParseException, JsonProcessingException {
        var jwtClaimsSet = verifiableCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var evidence = vc.getAsString(EVIDENCE);
        return new AuditExtensionsVcEvidence(jwtClaimsSet.getIssuer(), evidence);
    }

    @Tracing
    private void submitVcToCiStorage(SignedJWT vc, String govukSigninJourneyId)
            throws CiPutException {
        ciStorageService.submitVC(vc, govukSigninJourneyId);
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
