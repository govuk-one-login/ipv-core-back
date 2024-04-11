package uk.gov.di.ipv.core.builduseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsUserIdentity;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.AuditEventReturnCode;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SESSION_CREDENTIALS_TABLE_READS;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.TICF_CRI_BETA;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

public class BuildUserIdentityHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final ConfigService configService;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CiMitService ciMitService;
    private final CiMitUtilityService ciMitUtilityService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final SessionCredentialsService sessionCredentialsService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public BuildUserIdentityHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildUserIdentityHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ciMitService = new CiMitService(configService);
        this.ciMitUtilityService = new CiMitUtilityService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentId(configService);
        try {
            AccessToken accessToken =
                    AccessToken.parse(
                            RequestHelper.getHeaderByKey(
                                    input.getHeaders(), AUTHORIZATION_HEADER_KEY),
                            AccessTokenType.BEARER);

            IpvSessionItem ipvSessionItem =
                    ipvSessionService
                            .getIpvSessionByAccessToken(accessToken.getValue())
                            .orElse(null);

            if (Objects.isNull((ipvSessionItem))) {
                return getUnknownAccessTokenApiGatewayProxyResponseEvent();
            }

            configService.setFeatureSet(ipvSessionItem.getFeatureSetAsList());

            AccessTokenMetadata accessTokenMetadata = ipvSessionItem.getAccessTokenMetadata();

            if (StringUtils.isNotBlank(accessTokenMetadata.getRevokedAtDateTime())) {
                return getRevokedAccessTokenApiGatewayProxyResponseEvent(accessTokenMetadata);
            }

            if (accessTokenHasExpired(accessTokenMetadata)) {
                return getExpiredAccessTokenApiGatewayProxyResponseEvent(accessTokenMetadata);
            }

            String ipvSessionId = ipvSessionItem.getIpvSessionId();
            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            LogHelper.attachClientIdToLogs(clientOAuthSessionItem.getClientId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            String userId = clientOAuthSessionItem.getUserId();
            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            userId,
                            ipvSessionId,
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            null);

            var contraIndicatorsVc =
                    ciMitService.getContraIndicatorsVc(
                            userId, clientOAuthSessionItem.getGovukSigninJourneyId(), null);

            var contraIndicators = ciMitService.getContraIndicators(contraIndicatorsVc);

            var vcs =
                    configService.enabled(SESSION_CREDENTIALS_TABLE_READS)
                            ? sessionCredentialsService.getLatestCredentialsByIssuer(
                                    ipvSessionId, userId)
                            : verifiableCredentialService.getVcs(userId);

            UserIdentity userIdentity =
                    userIdentityService.generateUserIdentity(
                            vcs, userId, ipvSessionItem.getVot(), contraIndicators);
            userIdentity.getVcs().add(contraIndicatorsVc.getVcString());
            if (configService.enabled(TICF_CRI_BETA)
                    && (ipvSessionItem.getRiskAssessmentCredential() != null)) {
                userIdentity.getVcs().add(ipvSessionItem.getRiskAssessmentCredential());
            }

            sendIdentityIssuedAuditEvent(
                    ipvSessionItem, auditEventUser, contraIndicators, userIdentity);

            ipvSessionService.revokeAccessToken(ipvSessionItem);

            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_LAMBDA_RESULT.getFieldName(),
                                    "Successfully generated user identity response.")
                            .with(LOG_VOT.getFieldName(), ipvSessionItem.getVot());
            LOGGER.info(message);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HTTPResponse.SC_OK, userIdentity);
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to parse access token"));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (SqsException e) {
            return serverErrorJsonResponse("Failed to send audit event to SQS queue.", e);
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return errorResponseJsonResponse(e.getResponseCode(), e.getErrorResponse());
        } catch (CiRetrievalException e) {
            return serverErrorJsonResponse("Error when fetching CIs from storage system.", e);
        } catch (CredentialParseException e) {
            return serverErrorJsonResponse("Failed to parse successful VC Store items.", e);
        } catch (UnrecognisedCiException e) {
            return serverErrorJsonResponse("CI error.", e);
        }
    }

    private void sendIdentityIssuedAuditEvent(
            IpvSessionItem ipvSessionItem,
            AuditEventUser auditEventUser,
            ContraIndicators contraIndicators,
            UserIdentity userIdentity)
            throws SqsException {

        Map<String, ContraIndicatorConfig> configMap = configService.getContraIndicatorConfigMap();
        var auditEventReturnCodes =
                userIdentity.getReturnCode().stream()
                        .map(
                                returnCode ->
                                        getAuditEventReturnCodes(
                                                returnCode, contraIndicators, configMap))
                        .toList();

        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity(
                        ipvSessionItem.getVot(),
                        ciMitUtilityService.isBreachingCiThreshold(contraIndicators),
                        contraIndicators.hasMitigations(),
                        auditEventReturnCodes);

        LOGGER.info(LogHelper.buildLogMessage("Sending audit event IPV_IDENTITY_ISSUED message."));
        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_IDENTITY_ISSUED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        extensions));
    }

    private AuditEventReturnCode getAuditEventReturnCodes(
            ReturnCode returnCode,
            ContraIndicators contraIndicators,
            Map<String, ContraIndicatorConfig> ciConfig) {
        var issuers =
                contraIndicators.getUsersContraIndicators().stream()
                        .filter(
                                ci ->
                                        ciConfig.get(ci.getCode())
                                                .getReturnCode()
                                                .equals(returnCode.code()))
                        .flatMap(ci -> ci.getIssuers().stream())
                        .distinct()
                        .toList();
        return new AuditEventReturnCode(returnCode.code(), issuers);
    }

    private APIGatewayProxyResponseEvent getExpiredAccessTokenApiGatewayProxyResponseEvent(
            AccessTokenMetadata accessTokenMetadata) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token expired at: {}",
                accessTokenMetadata.getExpiryDateTime());
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .toJSONObject());
    }

    private APIGatewayProxyResponseEvent getRevokedAccessTokenApiGatewayProxyResponseEvent(
            AccessTokenMetadata accessTokenMetadata) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token has been revoked at: {}",
                accessTokenMetadata.getRevokedAtDateTime());
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has been revoked")
                        .toJSONObject());
    }

    private APIGatewayProxyResponseEvent getUnknownAccessTokenApiGatewayProxyResponseEvent() {
        LOGGER.error(
                LogHelper.buildLogMessage(
                        "User credential could not be retrieved. The supplied access token was not found in the database."));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - The supplied access token was not found in the database")
                        .toJSONObject());
    }

    private boolean accessTokenHasExpired(AccessTokenMetadata accessTokenMetadata) {
        if (StringUtils.isNotBlank(accessTokenMetadata.getExpiryDateTime())) {
            return Instant.now().isAfter(Instant.parse(accessTokenMetadata.getExpiryDateTime()));
        }
        return false;
    }

    private APIGatewayProxyResponseEvent errorResponseJsonResponse(
            int httpStatusCode, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildLogMessage(errorResponse.getMessage()));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                httpStatusCode, errorResponse.toResponseBody());
    }

    private APIGatewayProxyResponseEvent serverErrorJsonResponse(String errorHeader, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorHeader, e));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                OAuth2Error.SERVER_ERROR
                        .appendDescription(" - " + errorHeader + " " + e.getMessage())
                        .toJSONObject());
    }
}
