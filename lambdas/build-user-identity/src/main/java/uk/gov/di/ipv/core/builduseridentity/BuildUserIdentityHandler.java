package uk.gov.di.ipv.core.builduseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsUserIdentity;
import uk.gov.di.ipv.core.library.domain.AuditEventReturnCode;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.ExpiredAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.InvalidScopeException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.RevokedAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.VotHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.ContraIndicator;

import java.io.UncheckedIOException;
import java.net.URI;
import java.util.List;
import java.util.Map;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_SECURITY_CHECK_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.OPENID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

public class BuildUserIdentityHandler extends UserIdentityRequestHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final UserIdentityService userIdentityService;
    private final AuditService auditService;
    private final CimitUtilityService cimitUtilityService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public BuildUserIdentityHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CimitUtilityService cimitUtilityService,
            SessionCredentialsService sessionCredentialsService) {
        super(
                OPENID,
                ipvSessionService,
                configService,
                clientOAuthSessionDetailsService,
                sessionCredentialsService);
        this.userIdentityService = userIdentityService;
        this.auditService = auditService;
        this.cimitUtilityService = cimitUtilityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildUserIdentityHandler() {
        super(OPENID);
        this.userIdentityService = new UserIdentityService(configService);
        this.auditService = AuditService.create(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            var ipvSessionItem = super.validateAccessTokenAndGetIpvSession(input);
            var clientOAuthSessionItem =
                    super.getClientOAuthSessionItem(ipvSessionItem.getClientOAuthSessionId());

            var ipvSessionId = ipvSessionItem.getIpvSessionId();
            var userId = clientOAuthSessionItem.getUserId();
            var auditEventUser =
                    new AuditEventUser(
                            userId,
                            ipvSessionId,
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            null);

            if (StringUtils.isBlank(ipvSessionItem.getSecurityCheckCredential())) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                        OAuth2Error.SERVER_ERROR
                                .appendDescription(
                                        " - " + MISSING_SECURITY_CHECK_CREDENTIAL.getMessage())
                                .toJSONObject());
            }

            var contraIndicators =
                    cimitUtilityService.getContraIndicatorsFromVc(
                            ipvSessionItem.getSecurityCheckCredential(),
                            clientOAuthSessionItem.getUserId());

            var vcs = sessionCredentialsService.getCredentials(ipvSessionId, userId);

            var achievedVot = ipvSessionItem.getVot();
            var thresholdVot = VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem);
            var userIdentity =
                    userIdentityService.generateUserIdentity(
                            vcs, userId, achievedVot, thresholdVot, contraIndicators);
            userIdentity.getVcs().add(ipvSessionItem.getSecurityCheckCredential());

            if (configService.isCredentialIssuerEnabled(TICF.getId())
                    && (ipvSessionItem.getRiskAssessmentCredential() != null)) {
                userIdentity.getVcs().add(ipvSessionItem.getRiskAssessmentCredential());
            }

            sendIdentityIssuedAuditEvent(
                    achievedVot, thresholdVot, auditEventUser, contraIndicators, userIdentity);

            closeSession(ipvSessionItem);

            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_LAMBDA_RESULT.getFieldName(),
                                    "Successfully generated user identity response.")
                            .with(LOG_VOT.getFieldName(), ipvSessionItem.getVot());
            LOGGER.info(message);

            EmbeddedMetricHelper.identityIssued(achievedVot);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HTTPResponse.SC_OK, userIdentity);
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to parse access token"));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return errorResponseJsonResponse(e.getResponseCode(), e.getErrorResponse());
        } catch (CiExtractionException e) {
            return serverErrorJsonResponse("Failed to extract contra indicators.", e);
        } catch (CredentialParseException e) {
            return serverErrorJsonResponse("Failed to parse successful VC Store items.", e);
        } catch (UnrecognisedCiException e) {
            return serverErrorJsonResponse("CI error.", e);
        } catch (RevokedAccessTokenException e) {
            return getRevokedAccessTokenApiGatewayProxyResponseEvent(e.getRevokedAt());
        } catch (ExpiredAccessTokenException e) {
            return getExpiredAccessTokenApiGatewayProxyResponseEvent(e.getExpiredAt());
        } catch (InvalidScopeException e) {
            return getAccessDeniedApiGatewayProxyResponseEvent();
        } catch (IpvSessionNotFoundException e) {
            return getUnknownAccessTokenApiGatewayProxyResponseEvent();
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

    private void sendIdentityIssuedAuditEvent(
            Vot achievedVot,
            Vot thresholdVot,
            AuditEventUser auditEventUser,
            List<ContraIndicator> contraIndicators,
            UserIdentity userIdentity) {

        var configMap = configService.getContraIndicatorConfigMap();
        var auditEventReturnCodes =
                userIdentity.getReturnCode().stream()
                        .map(
                                returnCode ->
                                        getAuditEventReturnCodes(
                                                returnCode, contraIndicators, configMap))
                        .toList();

        var extensions =
                new AuditExtensionsUserIdentity(
                        achievedVot,
                        cimitUtilityService.isBreachingCiThreshold(contraIndicators, thresholdVot),
                        contraIndicators.stream()
                                .anyMatch(ci -> !isNullOrEmpty(ci.getMitigation())),
                        auditEventReturnCodes);

        LOGGER.info(LogHelper.buildLogMessage("Sending audit event IPV_IDENTITY_ISSUED message."));
        auditService.sendAuditEvent(
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_IDENTITY_ISSUED,
                        configService.getComponentId(),
                        auditEventUser,
                        extensions));
    }

    private AuditEventReturnCode getAuditEventReturnCodes(
            ReturnCode returnCode,
            List<ContraIndicator> contraIndicators,
            Map<String, ContraIndicatorConfig> ciConfigMap) {
        var issuers =
                contraIndicators.stream()
                        .filter(
                                ci -> {
                                    var ciConfig = ciConfigMap.get(ci.getCode());
                                    return ciConfig != null
                                            && ciConfig.getReturnCode().equals(returnCode.code());
                                })
                        .flatMap(ci -> ci.getIssuers().stream())
                        .map(URI::toString)
                        .distinct()
                        .toList();
        return new AuditEventReturnCode(returnCode.code(), issuers);
    }

    private APIGatewayProxyResponseEvent errorResponseJsonResponse(
            int httpStatusCode, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildLogMessage(errorResponse.getMessage()));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                httpStatusCode, errorResponse.toResponseBody());
    }
}
