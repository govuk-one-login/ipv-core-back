package uk.gov.di.ipv.core.initialiseipvsession;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.initialiseipvsession.domain.InheritedIdentityJwtClaim;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarClaims;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarUserInfo;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsReproveIdentity;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator.CLAIMS_CLAIM;
import static uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsReproveIdentity.REPROVE_IDENTITY_KEY;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JAR_KMS_ENCRYPTION_KEY_ID;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;

public class InitialiseIpvSessionHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String IPV_SESSION_ID_KEY = "ipvSessionId";
    private static final String CLIENT_ID_PARAM_KEY = "clientId";
    private static final String REQUEST_PARAM_KEY = "request";
    private static final String REQUEST_GOV_UK_SIGN_IN_JOURNEY_ID_KEY = "govuk_signin_journey_id";
    private static final String REQUEST_EMAIL_ADDRESS_KEY = "email_address";
    private static final String REQUEST_VTR_KEY = "vtr";

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final VerifiableCredentialService verifiableCredentialService;

    private final KmsRsaDecrypter kmsRsaDecrypter;
    private final JarValidator jarValidator;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public InitialiseIpvSessionHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.kmsRsaDecrypter = new KmsRsaDecrypter();
        this.jarValidator = new JarValidator(kmsRsaDecrypter, configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public InitialiseIpvSessionHandler(
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            ConfigService configService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            VerifiableCredentialService verifiableCredentialService,
            KmsRsaDecrypter kmsRsaDecrypter,
            JarValidator jarValidator,
            AuditService auditService) {
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.configService = configService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.verifiableCredentialService = verifiableCredentialService;
        this.kmsRsaDecrypter = kmsRsaDecrypter;
        this.jarValidator = jarValidator;
        this.auditService = auditService;
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs(configService);

        try {
            String ipAddress = RequestHelper.getIpAddress(input);
            String featureSet = RequestHelper.getFeatureSet(input);
            configService.setFeatureSet(featureSet);
            Map<String, String> sessionParams =
                    OBJECT_MAPPER.readValue(input.getBody(), new TypeReference<>() {});
            Optional<ErrorResponse> error = validateSessionParams(sessionParams);
            if (error.isPresent()) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                "Validation of the client session params failed.",
                                error.get().getMessage()));
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, error.get());
            }

            SignedJWT signedJWT =
                    jarValidator.decryptJWE(
                            JWEObject.parse(sessionParams.get(REQUEST_PARAM_KEY)),
                            configService.getSsmParameter(JAR_KMS_ENCRYPTION_KEY_ID));
            JWTClaimsSet claimsSet =
                    jarValidator.validateRequestJwt(
                            signedJWT, sessionParams.get(CLIENT_ID_PARAM_KEY));

            String govukSigninJourneyId =
                    claimsSet.getStringClaim(REQUEST_GOV_UK_SIGN_IN_JOURNEY_ID_KEY);
            String emailAddress = claimsSet.getStringClaim(REQUEST_EMAIL_ADDRESS_KEY);
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<String> vtr = claimsSet.getStringListClaim(REQUEST_VTR_KEY);
            if (vtr == null || vtr.isEmpty() || vtr.stream().allMatch(String::isEmpty)) {
                LOGGER.error(LogHelper.buildLogMessage(ErrorResponse.MISSING_VTR.getMessage()));
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_VTR);
            }

            String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

            IpvSessionItem ipvSessionItem =
                    ipvSessionService.generateIpvSession(clientOAuthSessionId, null, emailAddress);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.generateClientSessionDetails(
                            clientOAuthSessionId,
                            claimsSet,
                            sessionParams.get(CLIENT_ID_PARAM_KEY));

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            clientOAuthSessionItem.getUserId(),
                            ipvSessionItem.getIpvSessionId(),
                            govukSigninJourneyId,
                            ipAddress);

            if (configService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)) {
                var inheritedIdentityJwtClaim = getInheritedIdentityClaim(claimsSet);
                if (inheritedIdentityJwtClaim.isPresent()) {
                    validateAndStoreHMRCInheritedIdentity(
                            clientOAuthSessionItem.getUserId(),
                            inheritedIdentityJwtClaim.get(),
                            claimsSet,
                            ipvSessionItem);
                }
            }

            Boolean reproveIdentity = claimsSet.getBooleanClaim(REPROVE_IDENTITY_KEY);

            AuditExtensionsReproveIdentity reproveAuditExtension =
                    reproveIdentity == null
                            ? null
                            : new AuditExtensionsReproveIdentity(reproveIdentity);

            AuditEvent auditEvent =
                    new AuditEvent(
                            AuditEventTypes.IPV_JOURNEY_START,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            reproveAuditExtension);

            auditService.sendAuditEvent(auditEvent);

            Map<String, String> response =
                    Map.of(IPV_SESSION_ID_KEY, ipvSessionItem.getIpvSessionId());

            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_LAMBDA_RESULT.getFieldName(),
                                    "Successfully generated a new IPV Core session")
                            .with(IPV_SESSION_ID_KEY, ipvSessionItem.getIpvSessionId());
            LOGGER.info(message);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
        } catch (RecoverableJarValidationException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Recoverable Jar validation failed.",
                            e.getErrorObject().getDescription()));

            String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

            IpvSessionItem ipvSessionItem =
                    ipvSessionService.generateIpvSession(
                            clientOAuthSessionId, e.getErrorObject(), null);
            clientOAuthSessionService.generateErrorClientSessionDetails(
                    clientOAuthSessionId,
                    e.getRedirectUri(),
                    e.getClientId(),
                    e.getState(),
                    e.getGovukSigninJourneyId());

            Map<String, String> response =
                    Map.of(IPV_SESSION_ID_KEY, ipvSessionItem.getIpvSessionId());

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse the decrypted JWE.", e));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (JarValidationException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Jar validation failed.", e.getErrorObject().getDescription()));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (SqsException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Failed to send audit event to SQS queue.", e));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse request body into map.", e));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse request body.", e));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IP_ADDRESS);
        }
    }

    private static Optional<InheritedIdentityJwtClaim> getInheritedIdentityClaim(
            JWTClaimsSet claimsSet) throws ParseException, RecoverableJarValidationException {
        try {
            return Optional.ofNullable(
                            OBJECT_MAPPER.convertValue(
                                    claimsSet.getJSONObjectClaim(CLAIMS_CLAIM), JarClaims.class))
                    .map(JarClaims::userInfo)
                    .map(JarUserInfo::inheritedIdentityClaim);
        } catch (IllegalArgumentException | ParseException e) {
            throw new RecoverableJarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Claims cannot be parsed to JarClaims"),
                    claimsSet,
                    e);
        }
    }

    @Tracing
    private void validateAndStoreHMRCInheritedIdentity(
            String userId,
            InheritedIdentityJwtClaim inheritedIdentityJwtClaim,
            JWTClaimsSet claimsSet,
            IpvSessionItem ipvSessionItem)
            throws RecoverableJarValidationException, ParseException {
        try {
            var signedInheritedIdentityJWT =
                    validateHmrcInheritedIdentity(userId, inheritedIdentityJwtClaim);
            storeHmrcInheritedIdentity(
                    userId, claimsSet, ipvSessionItem, signedInheritedIdentityJWT);
        } catch (VerifiableCredentialException | ParseException e) {
            throw new RecoverableJarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Inherited identity JWT failed to validate"),
                    claimsSet,
                    e);
        } catch (JarValidationException e) {
            throw new RecoverableJarValidationException(e.getErrorObject(), claimsSet, e);
        }
    }

    private SignedJWT validateHmrcInheritedIdentity(
            String userId, InheritedIdentityJwtClaim inheritedIdentityJwtClaim)
            throws JarValidationException, ParseException, VerifiableCredentialException {
        // Validate JAR claims structure is valid
        var inheritedIdentityJwtList =
                Optional.ofNullable(inheritedIdentityJwtClaim.values())
                        .orElseThrow(
                                () ->
                                        new JarValidationException(
                                                OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                                                        "Inherited identity jwt claim received but value is null")));
        if (inheritedIdentityJwtList.size() != 1) {
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            String.format(
                                    "%d inherited identity jwts received - one expected",
                                    inheritedIdentityJwtList.size())));
        }

        // Validate VC in claim is valid
        var signedInheritedIdentityJWT = SignedJWT.parse(inheritedIdentityJwtList.get(0));
        var inheritedIdentityCriConfig = configService.getCriConfig(HMRC_MIGRATION_CRI);

        verifiableCredentialJwtValidator.validate(
                signedInheritedIdentityJWT, inheritedIdentityCriConfig, userId);
        LOGGER.info(LogHelper.buildLogMessage("Migration VC successfully validated"));

        return signedInheritedIdentityJWT;
    }

    private void storeHmrcInheritedIdentity(
            String userId,
            JWTClaimsSet claimsSet,
            IpvSessionItem ipvSessionItem,
            SignedJWT signedInheritedIdentityJWT)
            throws RecoverableJarValidationException, ParseException {
        try {
            verifiableCredentialService.persistUserCredentials(
                    signedInheritedIdentityJWT, HMRC_MIGRATION_CRI, userId);
            ipvSessionItem.addVcReceivedThisSession(signedInheritedIdentityJWT.serialize());
            ipvSessionService.updateIpvSession(ipvSessionItem);
            LOGGER.info(LogHelper.buildLogMessage("Migration VC successfully persisted"));
        } catch (VerifiableCredentialException e) {
            throw new RecoverableJarValidationException(
                    OAuth2Error.SERVER_ERROR.setDescription(
                            "Failed to persist inherited identity JWT"),
                    claimsSet,
                    e);
        }
    }

    @Tracing
    private Optional<ErrorResponse> validateSessionParams(Map<String, String> sessionParams) {
        boolean isInvalid = false;

        if (StringUtils.isBlank(sessionParams.get(CLIENT_ID_PARAM_KEY))) {
            LOGGER.warn(LogHelper.buildLogMessage("Missing client_id query parameter"));
            isInvalid = true;
        }
        LogHelper.attachClientIdToLogs(sessionParams.get(CLIENT_ID_PARAM_KEY));

        if (StringUtils.isBlank(sessionParams.get(REQUEST_PARAM_KEY))) {
            LOGGER.warn(LogHelper.buildLogMessage("Missing request query parameter"));
            isInvalid = true;
        }

        if (isInvalid) {
            return Optional.of(ErrorResponse.INVALID_SESSION_REQUEST);
        }
        return Optional.empty();
    }
}
