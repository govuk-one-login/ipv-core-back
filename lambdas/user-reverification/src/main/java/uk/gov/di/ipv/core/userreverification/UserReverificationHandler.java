package uk.gov.di.ipv.core.userreverification;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.builduseridentity.UserIdentityRequestHandler;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionReverification;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ReverificationFailureCode;
import uk.gov.di.ipv.core.library.domain.ReverificationResponse;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.ExpiredAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.InvalidScopeException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.RevokedAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.io.UncheckedIOException;

import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;

public class UserReverificationHandler extends UserIdentityRequestHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final AuditService auditService;

    private static final ReverificationFailureCode DEFAULT_FAILURE_CODE =
            ReverificationFailureCode.IDENTITY_CHECK_INCOMPLETE;

    @ExcludeFromGeneratedCoverageReport
    public UserReverificationHandler(
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            SessionCredentialsService sessionCredentialsService) {

        super(
                REVERIFICATION,
                ipvSessionService,
                configService,
                clientOAuthSessionDetailsService,
                sessionCredentialsService);
        this.auditService = AuditService.create(configService);
    }

    public UserReverificationHandler(
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            SessionCredentialsService sessionCredentialsService,
            AuditService auditService) {

        super(
                REVERIFICATION,
                ipvSessionService,
                configService,
                clientOAuthSessionDetailsService,
                sessionCredentialsService);
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public UserReverificationHandler() {
        super(REVERIFICATION);

        var configService = ConfigService.create();
        this.auditService = AuditService.create(configService);
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
            String userId = clientOAuthSessionItem.getUserId();

            closeSession(ipvSessionItem);

            ReverificationResponse response;
            if (ipvSessionItem.getReverificationStatus() != null
                    && ipvSessionItem
                            .getReverificationStatus()
                            .equals(ReverificationStatus.SUCCESS)) {
                response = ReverificationResponse.successResponse(userId);
            } else {

                var failureCode =
                        ipvSessionItem.getFailureCode() != null
                                ? ipvSessionItem.getFailureCode()
                                : DEFAULT_FAILURE_CODE;

                response = ReverificationResponse.failureResponse(userId, failureCode);
            }

            var reverificationEndAuditEvent =
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_REVERIFY_END,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            new AuditEventUser(
                                    userId,
                                    ipvSessionItem.getIpvSessionId(),
                                    clientOAuthSessionItem.getGovukSigninJourneyId(),
                                    null),
                            new AuditExtensionReverification(
                                    response.success(), response.failureCode()));
            auditService.sendAuditEvent(reverificationEndAuditEvent);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HTTPResponse.SC_OK, response);
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to parse access token"));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (UnrecognisedCiException e) {
            return serverErrorJsonResponse("CI error.", e);
        } catch (RevokedAccessTokenException e) {
            return getRevokedAccessTokenApiGatewayProxyResponseEvent(e.getRevokedAt());
        } catch (ExpiredAccessTokenException e) {
            return getExpiredAccessTokenApiGatewayProxyResponseEvent(e.getExpiredAt());
        } catch (InvalidScopeException e) {
            return getAccessDeniedApiGatewayProxyResponseEvent();
        } catch (IpvSessionNotFoundException | ClientOauthSessionNotFoundException e) {
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
}
