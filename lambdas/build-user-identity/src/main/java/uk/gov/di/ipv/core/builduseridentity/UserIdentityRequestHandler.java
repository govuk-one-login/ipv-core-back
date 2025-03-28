package uk.gov.di.ipv.core.builduseridentity;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.ExpiredAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.InvalidScopeException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.RevokedAccessTokenException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.time.Instant;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;

public abstract class UserIdentityRequestHandler {
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    protected static final Logger LOGGER = LogManager.getLogger();
    protected final IpvSessionService ipvSessionService;
    protected final ConfigService configService;
    protected final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    protected final SessionCredentialsService sessionCredentialsService;
    private final String allowedScope;

    @ExcludeFromGeneratedCoverageReport
    protected UserIdentityRequestHandler(String allowedScope) {
        this.allowedScope = allowedScope;
        this.configService = ConfigService.create();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
    }

    protected UserIdentityRequestHandler(
            String allowedScope,
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            SessionCredentialsService sessionCredentialsService) {
        this.allowedScope = allowedScope;
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    protected IpvSessionItem validateAccessTokenAndGetIpvSession(APIGatewayProxyRequestEvent input)
            throws ParseException,
                    RevokedAccessTokenException,
                    ExpiredAccessTokenException,
                    IpvSessionNotFoundException {

        LogHelper.attachComponentId(configService);

        AccessToken accessToken =
                AccessToken.parse(
                        RequestHelper.getHeaderByKey(input.getHeaders(), AUTHORIZATION_HEADER_KEY),
                        AccessTokenType.BEARER);

        IpvSessionItem ipvSessionItem =
                ipvSessionService.getIpvSessionByAccessToken(accessToken.getValue());

        configService.setFeatureSet(ipvSessionItem.getFeatureSetAsList());

        String revokedAt = ipvSessionItem.getAccessTokenMetadata().getRevokedAtDateTime();
        if (StringUtils.isNotBlank(revokedAt)) {
            throw new RevokedAccessTokenException(
                    "The supplied access token has been revoked", revokedAt);
        }

        String expiredAt = ipvSessionItem.getAccessTokenMetadata().getExpiryDateTime();
        if (StringUtils.isNotBlank(expiredAt) && Instant.now().isAfter(Instant.parse(expiredAt))) {
            throw new ExpiredAccessTokenException(
                    "User credential could not be retrieved. The supplied access token expired at: "
                            + expiredAt,
                    expiredAt);
        }

        String ipvSessionId = ipvSessionItem.getIpvSessionId();
        LogHelper.attachIpvSessionIdToLogs(ipvSessionId);

        return ipvSessionItem;
    }

    protected ClientOAuthSessionItem getClientOAuthSessionItem(String clientOAuthSessionId)
            throws InvalidScopeException, ClientOauthSessionNotFoundException {
        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(clientOAuthSessionId);

        LogHelper.attachClientIdToLogs(clientOAuthSessionItem.getClientId());
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());

        var scopeClaims = clientOAuthSessionItem.getScopeClaims();
        if (configService.enabled(MFA_RESET) && !scopeClaims.contains(this.allowedScope)) {
            throw new InvalidScopeException();
        }
        return clientOAuthSessionItem;
    }

    protected void closeSession(IpvSessionItem ipvSessionItem) {
        // Invalidate the access token
        ipvSessionService.revokeAccessToken(ipvSessionItem);
        try {
            // Clear the session VC store
            sessionCredentialsService.deleteSessionCredentials(ipvSessionItem.getIpvSessionId());
        } catch (VerifiableCredentialException e) {
            // just log the error - it should get deleted after a fixed time period anyway
            LOGGER.error(
                    LogHelper.buildLogMessage("Failed to delete session credential from store"));
        }
    }

    protected APIGatewayProxyResponseEvent getExpiredAccessTokenApiGatewayProxyResponseEvent(
            String expiryTime) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token expired at: {}",
                expiryTime);
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .toJSONObject());
    }

    protected APIGatewayProxyResponseEvent getRevokedAccessTokenApiGatewayProxyResponseEvent(
            String revokedTime) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token has been revoked at: {}",
                revokedTime);
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has been revoked")
                        .toJSONObject());
    }

    protected APIGatewayProxyResponseEvent getUnknownAccessTokenApiGatewayProxyResponseEvent() {
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

    protected APIGatewayProxyResponseEvent serverErrorJsonResponse(
            String errorHeader, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorHeader, e));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                OAuth2Error.SERVER_ERROR
                        .appendDescription(" - " + errorHeader + " " + e.getMessage())
                        .toJSONObject());
    }

    protected APIGatewayProxyResponseEvent getAccessDeniedApiGatewayProxyResponseEvent() {
        LOGGER.error(
                LogHelper.buildLogMessage(
                        "Access denied. Access was attempted from an invalid endpoint or journey."));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - Access was attempted from an invalid endpoint or journey.")
                        .toJSONObject());
    }
}
