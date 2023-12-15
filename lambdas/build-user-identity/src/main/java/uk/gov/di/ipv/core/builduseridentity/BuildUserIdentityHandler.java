package uk.gov.di.ipv.core.builduseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
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

import java.time.Instant;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_ALWAYS_REQUIRED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_NON_CI_BREACHING_P0;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
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

    public BuildUserIdentityHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
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
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
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

            configService.setFeatureSet(ipvSessionItem.getFeatureSet());

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

            SignedJWT signedCiMitJwt =
                    ciMitService.getContraIndicatorsVCJwt(
                            userId, clientOAuthSessionItem.getGovukSigninJourneyId(), null);

            ContraIndicators contraIndicators = ciMitService.getContraIndicators(signedCiMitJwt);
            UserIdentity userIdentity =
                    userIdentityService.generateUserIdentity(
                            userId, userId, ipvSessionItem.getVot(), contraIndicators);

            userIdentity.getVcs().add(signedCiMitJwt.serialize());

            sendIdentityIssuedAuditEvent(
                    ipvSessionItem, ipvSessionItem.getVot(), auditEventUser, contraIndicators);

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
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (SqsException e) {
            return serverErrorJsonResponse("Failed to send audit event to SQS queue.", e);
        } catch (HttpResponseExceptionWithErrorBody e) {
            LogHelper.logErrorMessage(
                    "Failed to generate the user identity output.", e.getErrorReason());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
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
            String vot,
            AuditEventUser auditEventUser,
            ContraIndicators contraIndicators)
            throws SqsException {
        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity(
                        ipvSessionItem.getVot(),
                        ciMitUtilityService.isBreachingCiThreshold(contraIndicators),
                        contraIndicators.hasMitigations(),
                        getReturnCodes(vot, contraIndicators));

        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "Sending audit event IPV_IDENTITY_ISSUED message."));
        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_IDENTITY_ISSUED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        extensions));
    }

    private List<AuditEventReturnCode> getReturnCodes(
            String vot, ContraIndicators contraIndicators) {
        Map<String, ContraIndicatorConfig> configMap = configService.getContraIndicatorConfigMap();
        var isBreachingCiThreshold = ciMitUtilityService.isBreachingCiThreshold(contraIndicators);
        List<AuditEventReturnCode> auditEventReturnCodes =
                getAuditEventReturnCodes(configMap, vot, contraIndicators, isBreachingCiThreshold);
        if (vot.equals(VectorOfTrust.P2.toString()) && !auditEventReturnCodes.isEmpty()) {
            return getSuccessReturnCode(auditEventReturnCodes);
        }
        return auditEventReturnCodes;
    }

    private List<AuditEventReturnCode> getSuccessReturnCode(
            List<AuditEventReturnCode> auditEventReturnCodes) throws UnrecognisedCiException {
        return auditEventReturnCodes.stream()
                .filter(
                        returnCode ->
                                configService
                                        .getSsmParameter(RETURN_CODES_ALWAYS_REQUIRED)
                                        .contains(returnCode.code()))
                .toList();
    }

    private List<AuditEventReturnCode> getAuditEventReturnCodes(
            Map<String, ContraIndicatorConfig> configMap,
            String vot,
            ContraIndicators contraIndicators,
            boolean isBreachingCiThreshold) {
        return contraIndicators.getContraIndicatorsMap().values().stream()
                .map(
                        contraIndicator -> {
                            ContraIndicatorConfig contraIndicatorConfig =
                                    configMap.get(contraIndicator.getCode());
                            String returnCode;
                            if (vot.equals(VectorOfTrust.P2.toString())) {
                                returnCode =
                                        contraIndicatorConfig != null
                                                ? contraIndicatorConfig.getReturnCode()
                                                : configService.getSsmParameter(
                                                        RETURN_CODES_ALWAYS_REQUIRED);
                            } else {
                                returnCode =
                                        isBreachingCiThreshold
                                                        && contraIndicator.getCode() != null
                                                        && contraIndicatorConfig != null
                                                ? contraIndicatorConfig.getReturnCode()
                                                : configService.getSsmParameter(
                                                        RETURN_CODES_NON_CI_BREACHING_P0);
                            }

                            List<String> issuers =
                                    contraIndicator.getIssuers() != null
                                                    && contraIndicators.hasMitigations()
                                            ? contraIndicator.getIssuers()
                                            : Collections.emptyList();
                            return Map.entry(
                                    Objects.requireNonNull(returnCode),
                                    issuers.stream().distinct().collect(Collectors.toList()));
                        })
                .collect(
                        Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (existing, replacement) -> {
                                    existing.addAll(replacement);
                                    return existing;
                                }))
                .entrySet()
                .stream()
                .sorted(Comparator.comparing(Map.Entry::getKey))
                .map(entry -> new AuditEventReturnCode(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());
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
                "User credential could not be retrieved. The supplied access token was not found in the database.");
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

    private APIGatewayProxyResponseEvent serverErrorJsonResponse(String errorHeader, Exception e) {
        LogHelper.logErrorMessage(errorHeader, e.getMessage());
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                OAuth2Error.SERVER_ERROR
                        .appendDescription(" - " + errorHeader + " " + e.getMessage())
                        .toJSONObject());
    }
}
