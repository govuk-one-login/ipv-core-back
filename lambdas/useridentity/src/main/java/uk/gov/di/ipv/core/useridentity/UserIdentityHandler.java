package uk.gov.di.ipv.core.useridentity;

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
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.core.library.service.AccessTokenService;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.time.Instant;
import java.util.Objects;

public class UserIdentityHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    private final UserIdentityService userIdentityService;
    private final AccessTokenService accessTokenService;
    private final IpvSessionService ipvSessionService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;

    public UserIdentityHandler(
            UserIdentityService userIdentityService,
            AccessTokenService accessTokenService,
            IpvSessionService ipvSessionService,
            ConfigurationService configurationService,
            AuditService auditService) {
        this.userIdentityService = userIdentityService;
        this.accessTokenService = accessTokenService;
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public UserIdentityHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.accessTokenService = new AccessTokenService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            AccessToken accessToken =
                    AccessToken.parse(
                            RequestHelper.getHeaderByKey(
                                    input.getHeaders(), AUTHORIZATION_HEADER_KEY),
                            AccessTokenType.BEARER);

            AccessTokenItem accessTokenItem =
                    accessTokenService.getAccessToken(accessToken.getValue());

            if (Objects.isNull((accessTokenItem))) {
                return getUnknownAccessTokenApiGatewayProxyResponseEvent();
            }

            if (StringUtils.isNotBlank(accessTokenItem.getRevokedAtDateTime())) {
                return getRevokedAccessTokenApiGatewayProxyResponseEvent(accessTokenItem);
            }

            if (accessTokenHasExpired(accessTokenItem)) {
                return getExpiredAccessTokenApiGatewayProxyResponseEvent(accessTokenItem);
            }

            String ipvSessionId = accessTokenItem.getIpvSessionId();
            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);

            ClientSessionDetailsDto clientSessionDetails =
                    ipvSessionService
                            .getIpvSession(accessTokenItem.getIpvSessionId())
                            .getClientSessionDetails();
            LogHelper.attachClientIdToLogs(clientSessionDetails.getClientId());

            UserIdentity userIdentity =
                    userIdentityService.generateUserIdentity(
                            ipvSessionId, clientSessionDetails.getUserId());

            auditService.sendAuditEvent(AuditEventTypes.IPV_IDENTITY_ISSUED);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HTTPResponse.SC_OK, userIdentity);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                    OAuth2Error.SERVER_ERROR.toJSONObject());
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Failed to generate the user identity output");
            return ApiGatewayResponseGenerator.proxyEmptyResponse(e.getResponseCode());
        }
    }

    private APIGatewayProxyResponseEvent getExpiredAccessTokenApiGatewayProxyResponseEvent(
            AccessTokenItem accessTokenItem) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token expired at: {}",
                accessTokenItem.getExpiryDateTime());
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .toJSONObject());
    }

    private APIGatewayProxyResponseEvent getRevokedAccessTokenApiGatewayProxyResponseEvent(
            AccessTokenItem accessTokenItem) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token has been revoked at: {}",
                accessTokenItem.getRevokedAtDateTime());
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

    private boolean accessTokenHasExpired(AccessTokenItem accessTokenItem) {
        if (StringUtils.isNotBlank(accessTokenItem.getExpiryDateTime())) {
            return Instant.now().isAfter(Instant.parse(accessTokenItem.getExpiryDateTime()));
        }
        return false;
    }
}
