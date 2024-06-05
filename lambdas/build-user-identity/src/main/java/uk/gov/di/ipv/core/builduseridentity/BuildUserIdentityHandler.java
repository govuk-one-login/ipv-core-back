package uk.gov.di.ipv.core.builduseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
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
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.ExpiredAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.InvalidScopeException;
import uk.gov.di.ipv.core.library.exceptions.RevokedAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnknownAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.Map;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.TICF_CRI_BETA;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.OPENID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

public class BuildUserIdentityHandler extends UserIdentityRequestHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final UserIdentityService userIdentityService;
    private final AuditService auditService;
    private final CiMitService ciMitService;
    private final CiMitUtilityService ciMitUtilityService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public BuildUserIdentityHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService,
            SessionCredentialsService sessionCredentialsService) {
        super(
                OPENID,
                ipvSessionService,
                configService,
                clientOAuthSessionDetailsService,
                sessionCredentialsService);
        this.userIdentityService = userIdentityService;
        this.auditService = auditService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildUserIdentityHandler() {
        super(OPENID);
        this.userIdentityService = new UserIdentityService(configService);
        this.auditService = new AuditService(AuditService.getSqsClient(), configService);
        this.ciMitService = new CiMitService(configService);
        this.ciMitUtilityService = new CiMitUtilityService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            var ipvSessionItem = super.initialiseIpvSession(input);
            var clientOAuthSessionItem =
                    super.getClientOAuthSessionItem(input.getPath(), ipvSessionItem);

            String ipvSessionId = ipvSessionItem.getIpvSessionId();
            String userId = clientOAuthSessionItem.getUserId();
            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            clientOAuthSessionItem.getUserId(),
                            ipvSessionItem.getIpvSessionId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            null);

            var contraIndicatorsVc =
                    ciMitService.getContraIndicatorsVc(
                            userId, clientOAuthSessionItem.getGovukSigninJourneyId(), null);

            var contraIndicators = ciMitService.getContraIndicators(contraIndicatorsVc);

            var vcs = sessionCredentialsService.getCredentials(ipvSessionId, userId);

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

            deleteSessionCredentials(ipvSessionId);

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
        } catch (UnknownAccessTokenException e) {
            return getUnknownAccessTokenApiGatewayProxyResponseEvent();
        } catch (RevokedAccessTokenException e) {
            return getRevokedAccessTokenApiGatewayProxyResponseEvent(e.getRevokedAt());
        } catch (ExpiredAccessTokenException e) {
            return getExpiredAccessTokenApiGatewayProxyResponseEvent(e.getExpiredAt());
        } catch (InvalidScopeException e) {
            return getAccessDeniedApiGatewayProxyResponseEvent();
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

    private APIGatewayProxyResponseEvent errorResponseJsonResponse(
            int httpStatusCode, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildLogMessage(errorResponse.getMessage()));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                httpStatusCode, errorResponse.toResponseBody());
    }
}
