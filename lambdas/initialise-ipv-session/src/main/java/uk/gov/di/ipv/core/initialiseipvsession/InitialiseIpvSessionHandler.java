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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarClaims;
import uk.gov.di.ipv.core.initialiseipvsession.domain.JarUserInfo;
import uk.gov.di.ipv.core.initialiseipvsession.domain.StringListClaim;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.service.JweDecrypterFactory;
import uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsIpvJourneyStart;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.io.UncheckedIOException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator.CLAIMS_CLAIM;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;
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
    private static final ErrorObject EVCS_ACCESS_TOKEN_ERROR_OBJECT =
            new ErrorObject("invalid_evcs_access_token");
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;

    private final JarValidator jarValidator;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public InitialiseIpvSessionHandler() {
        this.configService = ConfigService.create();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.jarValidator =
                new JarValidator(
                        JweDecrypterFactory.create(configService),
                        configService,
                        new OAuthKeyService(configService));
        this.auditService = AuditService.create(configService);
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public InitialiseIpvSessionHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            JarValidator jarValidator,
            AuditService auditService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.jarValidator = jarValidator;
        this.auditService = auditService;
    }

    @SuppressWarnings("java:S3776") // Cognitive Complexity of methods should not be too high
    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachTraceId();
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
                        HttpStatusCode.BAD_REQUEST, error.get());
            }

            SignedJWT signedJWT =
                    jarValidator.decryptJWE(JWEObject.parse(sessionParams.get(REQUEST_PARAM_KEY)));

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
                        HttpStatusCode.BAD_REQUEST, ErrorResponse.MISSING_VTR);
            }

            String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.generateClientSessionDetails(
                            clientOAuthSessionId,
                            claimsSet,
                            sessionParams.get(CLIENT_ID_PARAM_KEY),
                            validateEvcsAccessToken(
                                    getJarUserInfo(claimsSet).map(JarUserInfo::evcsAccessToken),
                                    claimsSet));

            var isReproveIdentity =
                    Boolean.TRUE.equals(clientOAuthSessionItem.getReproveIdentity());

            IpvSessionItem ipvSessionItem =
                    ipvSessionService.generateIpvSession(
                            clientOAuthSessionId, null, emailAddress, isReverification, null);

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            clientOAuthSessionItem.getUserId(),
                            ipvSessionItem.getIpvSessionId(),
                            govukSigninJourneyId,
                            ipAddress);

            AuditExtensionsIpvJourneyStart extensionsIpvJourneyStart =
                    new AuditExtensionsIpvJourneyStart(isReproveIdentity ? true : null, vtr);

            var restrictedDeviceInformation =
                    new AuditRestrictedDeviceInformation(deviceInformation);

            AuditEvent auditEvent =
                    AuditEvent.createWithDeviceInformation(
                            AuditEventTypes.IPV_JOURNEY_START,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            extensionsIpvJourneyStart,
                            restrictedDeviceInformation);

            auditService.sendAuditEvent(auditEvent);

            if (isReverification) {
                AuditEvent reverificationAuditEvent =
                        AuditEvent.createWithDeviceInformation(
                                AuditEventTypes.IPV_REVERIFY_START,
                                configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser,
                                restrictedDeviceInformation);
                auditService.sendAuditEvent(reverificationAuditEvent);
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

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatusCode.OK, response);
        } catch (RecoverableJarValidationException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Recoverable Jar validation failed.",
                            e.getErrorObject().getDescription()));

            String clientOAuthSessionId = SecureTokenHelper.getInstance().generate();

            IpvSessionItem ipvSessionItem =
                    ipvSessionService.generateIpvSession(
                            clientOAuthSessionId,
                            e.getErrorObject(),
                            null,
                            false,
                            new AccountInterventionState(false, false, false, false));
            clientOAuthSessionService.generateErrorClientSessionDetails(
                    clientOAuthSessionId,
                    e.getRedirectUri(),
                    e.getClientId(),
                    e.getState(),
                    e.getGovukSigninJourneyId());

            Map<String, String> response =
                    Map.of(IPV_SESSION_ID_KEY, ipvSessionItem.getIpvSessionId());

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatusCode.OK, response);
        } catch (ParseException e) {
            // Doesn't match all the potential causes
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse the decrypted JWE.", e));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (JarValidationException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Jar validation failed.", e.getErrorObject().getDescription()));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse request body into map.", e));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        } catch (UncheckedIOException e) {
            // Temporary mitigation to force lambda instance to crash and restart by explicitly
            // exiting the program on fatal IOException - see PYIC-8220 and incident INC0014398.
            LOGGER.error("Crashing on UncheckedIOException", e);
            System.exit(1);
            return null;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
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

    private static boolean isListEmpty(List<String> list) {
        return list == null || list.isEmpty() || list.stream().allMatch(String::isEmpty);
    }

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
