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
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarClaims;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarUserInfo;
import uk.gov.di.ipv.core.initialiseipvsession.domain.StringListClaim;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionAccountIntervention;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsIpvJourneyStart;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
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
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator.CLAIMS_CLAIM;
import static uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsIpvJourneyStart.REPROVE_IDENTITY_KEY;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;
import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getRestrictedAuditDataForInheritedIdentity;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JAR_KMS_ENCRYPTION_KEY_ID;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_TOKEN_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.SCOPE;
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
    private static final List<Vot> HMRC_PROFILES_BY_STRENGTH = List.of(Vot.PCL250, Vot.PCL200);
    private static final ErrorObject INVALID_INHERITED_IDENTITY_ERROR_OBJECT =
            new ErrorObject("invalid_inherited_identity");
    private static final ErrorObject EVCS_ACCESS_TOKEN_ERROR_OBJECT =
            new ErrorObject("invalid_evcs_access_token");
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final UserIdentityService userIdentityService;
    private final VerifiableCredentialValidator verifiableCredentialValidator;
    private final VerifiableCredentialService verifiableCredentialService;

    private final KmsRsaDecrypter kmsRsaDecrypter;
    private final JarValidator jarValidator;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public InitialiseIpvSessionHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.kmsRsaDecrypter = new KmsRsaDecrypter();
        this.jarValidator = new JarValidator(kmsRsaDecrypter, configService);
        this.auditService = new AuditService(AuditService.getSqsClient(), configService);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public InitialiseIpvSessionHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            UserIdentityService userIdentityService,
            VerifiableCredentialValidator verifiableCredentialValidator,
            VerifiableCredentialService verifiableCredentialService,
            KmsRsaDecrypter kmsRsaDecrypter,
            JarValidator jarValidator,
            AuditService auditService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.userIdentityService = userIdentityService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
        this.verifiableCredentialService = verifiableCredentialService;
        this.kmsRsaDecrypter = kmsRsaDecrypter;
        this.jarValidator = jarValidator;
        this.auditService = auditService;
    }

    @SuppressWarnings("java:S3776") // Cognitive Complexity of methods should not be too high
    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            String ipAddress = RequestHelper.getIpAddress(input);
            String deviceInformation = RequestHelper.getEncodedDeviceInformation(input);
            configService.setFeatureSet(RequestHelper.getFeatureSet(input));
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

            var isReverification =
                    configService.enabled(MFA_RESET)
                            && Scope.parse(claimsSet.getStringClaim(SCOPE))
                                    .contains(REVERIFICATION);
            if (!isReverification && isListEmpty(vtr)) {
                LOGGER.error(LogHelper.buildLogMessage(ErrorResponse.MISSING_VTR.getMessage()));
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_VTR);
            }

            String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

            IpvSessionItem ipvSessionItem =
                    ipvSessionService.generateIpvSession(
                            clientOAuthSessionId, null, emailAddress, isReverification);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.generateClientSessionDetails(
                            clientOAuthSessionId,
                            claimsSet,
                            sessionParams.get(CLIENT_ID_PARAM_KEY),
                            getEvcsAccessToken(claimsSet));

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            clientOAuthSessionItem.getUserId(),
                            ipvSessionItem.getIpvSessionId(),
                            govukSigninJourneyId,
                            ipAddress);

            if (configService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)) {
                var inheritedIdentityJwtClaim =
                        getJarUserInfo(claimsSet).map(JarUserInfo::inheritedIdentityClaim);
                if (inheritedIdentityJwtClaim.isPresent()) {
                    validateAndStoreHMRCInheritedIdentity(
                            clientOAuthSessionItem.getUserId(),
                            inheritedIdentityJwtClaim.get(),
                            claimsSet,
                            ipvSessionItem,
                            auditEventUser,
                            deviceInformation);
                }
            }

            var isReproveIdentity = isReproveIdentity(claimsSet);
            AuditExtensionsIpvJourneyStart extensionsIpvJourneyStart =
                    new AuditExtensionsIpvJourneyStart(isReproveIdentity, vtr);

            AuditEvent auditEvent =
                    AuditEvent.createWithDeviceInformation(
                            AuditEventTypes.IPV_JOURNEY_START,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            extensionsIpvJourneyStart,
                            new AuditRestrictedDeviceInformation(deviceInformation));

            auditService.sendAuditEvent(auditEvent);

            if (Boolean.TRUE.equals(isReproveIdentity)) {
                auditService.sendAuditEvent(
                        AuditEvent.createWithoutDeviceInformation(
                                AuditEventTypes.IPV_ACCOUNT_INTERVENTION_START,
                                configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser,
                                AuditExtensionAccountIntervention.newReproveIdentity()));
            }

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
                            clientOAuthSessionId, e.getErrorObject(), null, false);
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
            // Doesn't match all the potential causes
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
        } catch (CredentialParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Failed to check if stronger vot vc present.", e));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        }
    }

    private Optional<JarUserInfo> getJarUserInfo(JWTClaimsSet claimsSet)
            throws ParseException, RecoverableJarValidationException {
        try {
            return Optional.ofNullable(
                            OBJECT_MAPPER.convertValue(
                                    claimsSet.getJSONObjectClaim(CLAIMS_CLAIM), JarClaims.class))
                    .map(JarClaims::userinfo);
        } catch (IllegalArgumentException | ParseException e) {
            throw new RecoverableJarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Claims cannot be parsed to JarClaims"),
                    claimsSet,
                    e);
        }
    }

    private Boolean isReproveIdentity(JWTClaimsSet claimsSet) throws ParseException {
        return configService.enabled(CoreFeatureFlag.REPROVE_IDENTITY_ENABLED)
                ? claimsSet.getBooleanClaim(REPROVE_IDENTITY_KEY)
                : null;
    }

    private static boolean isListEmpty(List<String> list) {
        return list == null || list.isEmpty() || list.stream().allMatch(String::isEmpty);
    }

    @Tracing
    private void validateAndStoreHMRCInheritedIdentity(
            String userId,
            StringListClaim inheritedIdentityJwtClaim,
            JWTClaimsSet claimsSet,
            IpvSessionItem ipvSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation)
            throws RecoverableJarValidationException, ParseException, CredentialParseException,
                    SqsException {
        try {
            var inheritedIdentityVc =
                    validateHmrcInheritedIdentity(userId, inheritedIdentityJwtClaim);
            sendInheritedIdentityReceivedAuditEvent(
                    inheritedIdentityVc, auditEventUser, deviceInformation);
            if (!isHmrcInheritedIdentityWithStrongerVotPresent(inheritedIdentityVc, userId)) {
                storeHmrcInheritedIdentity(claimsSet, ipvSessionItem, inheritedIdentityVc);
            }
        } catch (VerifiableCredentialException | ParseException | UnrecognisedVotException e) {
            throw new RecoverableJarValidationException(
                    INVALID_INHERITED_IDENTITY_ERROR_OBJECT.setDescription(
                            "Inherited identity JWT failed to validate"),
                    claimsSet,
                    e);
        } catch (JarValidationException e) {
            throw new RecoverableJarValidationException(e.getErrorObject(), claimsSet, e);
        }
    }

    @Tracing
    private String getEvcsAccessToken(JWTClaimsSet claimsSet)
            throws RecoverableJarValidationException, ParseException {

        var writeEnabled = configService.enabled(EVCS_WRITE_ENABLED);
        var readEnabled = configService.enabled(EVCS_READ_ENABLED);
        if (!configService.enabled(EVCS_TOKEN_READ_ENABLED) && !writeEnabled && !readEnabled) {
            return null;
        }
        try {
            return validateEvcsAccessToken(
                    getJarUserInfo(claimsSet).map(JarUserInfo::evcsAccessToken), claimsSet);
        } catch (RecoverableJarValidationException | ParseException e) {
            if (writeEnabled || readEnabled) {
                throw e;
            } else {
                return null;
            }
        }
    }

    @Tracing
    private String validateEvcsAccessToken(
            Optional<StringListClaim> evcsAccessTokenClaim, JWTClaimsSet claimsSet)
            throws RecoverableJarValidationException, ParseException {
        try {
            // Validate JAR claims structure is valid
            var evcsAccessTokenList =
                    Optional.ofNullable(
                                    evcsAccessTokenClaim
                                            .orElseThrow(
                                                    () ->
                                                            new JarValidationException(
                                                                    EVCS_ACCESS_TOKEN_ERROR_OBJECT
                                                                            .setDescription(
                                                                                    "Evcs access token jwt claim not received")))
                                            .values())
                            .orElseThrow(
                                    () ->
                                            new JarValidationException(
                                                    EVCS_ACCESS_TOKEN_ERROR_OBJECT.setDescription(
                                                            "Evcs access token jwt claim received but value is null")));
            if (evcsAccessTokenList.size() != 1) {
                throw new JarValidationException(
                        EVCS_ACCESS_TOKEN_ERROR_OBJECT.setDescription(
                                String.format(
                                        "%d EVCS access token received - one expected",
                                        evcsAccessTokenList.size())));
            }
            return evcsAccessTokenList.get(0);
        } catch (JarValidationException e) {
            throw new RecoverableJarValidationException(e.getErrorObject(), claimsSet, e);
        }
    }

    private VerifiableCredential validateHmrcInheritedIdentity(
            String userId, StringListClaim inheritedIdentityJwtClaim)
            throws JarValidationException, VerifiableCredentialException {
        // Validate JAR claims structure is valid
        var inheritedIdentityJwtList =
                Optional.ofNullable(inheritedIdentityJwtClaim.values())
                        .orElseThrow(
                                () ->
                                        new JarValidationException(
                                                INVALID_INHERITED_IDENTITY_ERROR_OBJECT
                                                        .setDescription(
                                                                "Inherited identity jwt claim received but value is null")));
        if (inheritedIdentityJwtList.size() != 1) {
            throw new JarValidationException(
                    INVALID_INHERITED_IDENTITY_ERROR_OBJECT.setDescription(
                            String.format(
                                    "%d inherited identity jwts received - one expected",
                                    inheritedIdentityJwtList.size())));
        }

        var inheritedIdentityCriConfig = configService.getCriConfig(HMRC_MIGRATION.getId());

        // The HMRC inherited identity VC will contain an HMRC-specific pairwise identifier
        // rather than our internal user id, so we cannot validate it against the OAuth user id.
        // Instead, SPOT will validate this when generating an identity bundle.
        var inheritedIdentityVc =
                verifiableCredentialValidator.parseAndValidate(
                        userId,
                        HMRC_MIGRATION,
                        inheritedIdentityJwtList.get(0),
                        inheritedIdentityCriConfig.getSigningKey(),
                        inheritedIdentityCriConfig.getComponentId(),
                        true);
        LOGGER.info(LogHelper.buildLogMessage("Migration VC successfully validated"));

        return inheritedIdentityVc;
    }

    private void storeHmrcInheritedIdentity(
            JWTClaimsSet claimsSet,
            IpvSessionItem ipvSessionItem,
            VerifiableCredential inheritedIdentityVc)
            throws RecoverableJarValidationException, ParseException {
        try {
            verifiableCredentialService.persistUserCredentials(inheritedIdentityVc);
            ipvSessionItem.setInheritedIdentityReceivedThisSession(true);
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

    private boolean isHmrcInheritedIdentityWithStrongerVotPresent(
            VerifiableCredential incomingInheritedIdentity, String userId)
            throws CredentialParseException {
        try {
            var hmrcMigrationVc = verifiableCredentialService.getVc(userId, HMRC_MIGRATION.getId());
            if (hmrcMigrationVc == null) {
                return false;
            }

            var existingInheritedIdentityVot = userIdentityService.getVot(hmrcMigrationVc);
            var incomingInheritedIdentityVot =
                    userIdentityService.getVot(incomingInheritedIdentity);

            var indexOfExistingVot =
                    HMRC_PROFILES_BY_STRENGTH.indexOf(existingInheritedIdentityVot);
            var indexOfIncomingVot =
                    HMRC_PROFILES_BY_STRENGTH.indexOf(incomingInheritedIdentityVot);

            if (indexOfExistingVot == -1 || indexOfIncomingVot == -1) {
                throw new IllegalArgumentException(
                        String.format(
                                "At least one of the existing (%s) or incoming (%s) VoTs from hmrc aren't expected",
                                existingInheritedIdentityVot, incomingInheritedIdentityVot));
            }

            return indexOfIncomingVot > indexOfExistingVot;
        } catch (ParseException | IllegalArgumentException e) {
            throw new CredentialParseException(
                    "Encountered a parsing error while attempting to parse credentials", e);
        }
    }

    private void sendInheritedIdentityReceivedAuditEvent(
            VerifiableCredential inheritedIdentityVc,
            AuditEventUser auditEventUser,
            String deviceInformation)
            throws SqsException, CredentialParseException, UnrecognisedVotException {
        try {
            auditService.sendAuditEvent(
                    AuditEvent.createWithDeviceInformation(
                            AuditEventTypes.IPV_INHERITED_IDENTITY_VC_RECEIVED,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            getExtensionsForAudit(inheritedIdentityVc, null),
                            getRestrictedAuditDataForInheritedIdentity(
                                    inheritedIdentityVc, deviceInformation)));
        } catch (IllegalArgumentException e) {
            throw new CredentialParseException(
                    "Encountered a parsing error while attempting to parse or compare credentials",
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
