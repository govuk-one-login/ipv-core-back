package uk.gov.di.ipv.core.userreverification;

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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.ReverificationResponse;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
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
import java.util.Arrays;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;

public class UserReverificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    private static final String REVERIFICATION_ENDPOINT = "/reverification";

    private final IpvSessionService ipvSessionService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final SessionCredentialsService sessionCredentialsService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public UserReverificationHandler(
            IpvSessionService ipvSessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            SessionCredentialsService sessionCredentialsService) {
        this.ipvSessionService = ipvSessionService;
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public UserReverificationHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
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

            var scopeClaims = clientOAuthSessionItem.getScope().split(" ");
            if (!input.getPath().contains(REVERIFICATION_ENDPOINT)
                    || !Arrays.asList(scopeClaims).contains(REVERIFICATION)) {
                return getAccessDeniedApiGatewayProxyResponseEvent();
            }

            // Invalidate the access token
            ipvSessionService.revokeAccessToken(ipvSessionItem);
            // Clear the session VC store
            deleteSessionCredentials(ipvSessionId);

            ReverificationResponse response;
            if (ipvSessionItem.getVot().equals(Vot.P2)) {
                response = ReverificationResponse.successResponse(userId);
            } else {
                response =
                        ReverificationResponse.failureResponse(
                                userId,
                                ipvSessionItem.getErrorCode(),
                                ipvSessionItem.getErrorDescription());
            }
            return ApiGatewayResponseGenerator.proxyJsonResponse(HTTPResponse.SC_OK, response);
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to parse access token"));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (UnrecognisedCiException e) {
            return serverErrorJsonResponse("CI error.", e);
        }
    }

    private void deleteSessionCredentials(String ipvSessionId) {
        try {
            sessionCredentialsService.deleteSessionCredentials(ipvSessionId);
        } catch (VerifiableCredentialException e) {
            // just log the error - it should get deleted after a fixed time period anyway
            LOGGER.error(
                    LogHelper.buildLogMessage("Failed to delete session credential from store"));
        }
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

    private APIGatewayProxyResponseEvent getAccessDeniedApiGatewayProxyResponseEvent() {
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
