package uk.gov.di.ipv.core.issueclientaccesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.issueclientaccesstoken.exception.ClientAuthenticationException;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.AccessTokenService;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.issueclientaccesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.io.UncheckedIOException;
import java.util.NoSuchElementException;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ACCESS_TOKEN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SHA256_ACCESS_TOKEN;

public class IssueClientAccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final AccessTokenService accessTokenService;
    private final IpvSessionService sessionService;
    private final ConfigService configService;
    private final TokenRequestValidator tokenRequestValidator;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;

    public IssueClientAccessTokenHandler(
            AccessTokenService accessTokenService,
            IpvSessionService sessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            TokenRequestValidator tokenRequestValidator) {
        this.accessTokenService = accessTokenService;
        this.sessionService = sessionService;
        this.configService = configService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.tokenRequestValidator = tokenRequestValidator;
    }

    @ExcludeFromGeneratedCoverageReport
    public IssueClientAccessTokenHandler() {
        this.configService = ConfigService.create();
        this.accessTokenService = new AccessTokenService(configService);
        this.sessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.tokenRequestValidator =
                new TokenRequestValidator(
                        configService,
                        new ClientAuthJwtIdService(configService),
                        new OAuthKeyService(configService));
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);
        try {
            tokenRequestValidator.authenticateClient(input.getBody());

            AuthorizationCodeGrant authorizationGrant =
                    (AuthorizationCodeGrant)
                            AuthorizationGrant.parse(URLUtils.parseParameters(input.getBody()));
            ValidationResult<ErrorObject> validationResult =
                    accessTokenService.validateAuthorizationGrant(authorizationGrant);
            if (!validationResult.isValid()) {
                ErrorObject error = validationResult.getError();
                LOGGER.error(LogHelper.buildErrorMessage("Invalid auth grant received.", error));
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        getHttpStatusCodeForErrorResponse(validationResult.getError()),
                        validationResult.getError().toJSONObject());
            }

            IpvSessionItem ipvSessionItem =
                    sessionService.getIpvSessionByAuthorizationCode(
                            authorizationGrant.getAuthorizationCode().getValue());

            configService.setFeatureSet(ipvSessionItem.getFeatureSetAsList());

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            LogHelper.attachIpvSessionIdToLogs(ipvSessionItem.getIpvSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            if (ipvSessionItem.getAccessToken() != null) {
                ErrorObject error = revokeAccessToken(ipvSessionItem);
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                "Auth code has been used multiple times", error));
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            AuthorizationCodeMetadata authorizationCodeMetadata =
                    ipvSessionItem.getAuthorizationCodeMetadata();

            if (authorizationCodeMetadata.isExpired(configService.getAuthCodeExpirySeconds())) {
                ErrorObject error =
                        OAuth2Error.INVALID_GRANT.setDescription("Authorization code expired");
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                String.format(
                                        "Access Token could not be issued. The supplied authorization code has expired. Created at: %s",
                                        ipvSessionItem
                                                .getAuthorizationCodeMetadata()
                                                .getCreationDateTime()),
                                error));
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            if (redirectUrlsDoNotMatch(authorizationCodeMetadata, authorizationGrant)) {
                ErrorObject error =
                        OAuth2Error.INVALID_GRANT.setDescription(
                                "Redirect URL in token request does not match redirect URL received in auth code request");

                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                String.format(
                                        "Invalid redirect URL value received. Session ID: %s",
                                        ipvSessionItem.getIpvSessionId()),
                                error));

                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            AccessTokenResponse accessTokenResponse =
                    accessTokenService.generateAccessToken().toSuccessResponse();

            if ("integration"
                    .equals(
                            configService.getEnvironmentVariable(
                                    EnvironmentVariable.ENVIRONMENT))) {
                BearerAccessToken bearerAccessToken =
                        accessTokenResponse.getTokens().getBearerAccessToken();
                var message =
                        new StringMapMessage()
                                .with(LOG_ACCESS_TOKEN.getFieldName(), bearerAccessToken.getValue())
                                .with(
                                        LOG_SHA256_ACCESS_TOKEN.getFieldName(),
                                        DigestUtils.sha256Hex(bearerAccessToken.getValue()));
                LOGGER.info(message);
            }

            sessionService.setAccessToken(
                    ipvSessionItem, accessTokenResponse.getTokens().getBearerAccessToken());

            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_LAMBDA_RESULT.getFieldName(),
                                    "Successfully generated IPV client access token.");
            LOGGER.info(message);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.OK, accessTokenResponse.toJSONObject());
        } catch (ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Token request could not be parsed", e.getErrorObject()));
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    getHttpStatusCodeForErrorResponse(e.getErrorObject()),
                    e.getErrorObject().toJSONObject());
        } catch (NoSuchElementException e) {
            ErrorObject error =
                    OAuth2Error.INVALID_GRANT.setDescription(
                            "The supplied authorization code was not found in the database");

            LOGGER.error(LogHelper.buildErrorMessage("Access Token could not be issued", error));

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    error.getHTTPStatusCode(), error.toJSONObject());
        } catch (ClientAuthenticationException e) {
            ErrorObject error =
                    OAuth2Error.INVALID_CLIENT.setDescription("Client authentication failed");

            LOGGER.error(LogHelper.buildErrorMessage("Client authentication failed", error));

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    error.getHTTPStatusCode(), error.toJSONObject());
        } catch (IpvSessionNotFoundException | ClientOauthSessionNotFoundException e) {
            ErrorObject error = OAuth2Error.INVALID_GRANT.setDescription(e.getMessage());

            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Error finding Ipv session for authorisation code", error));

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    error.getHTTPStatusCode(), error.toJSONObject());
        } catch (UncheckedIOException e) {
            // Temporary mitigation to force lambda instance to crash and restart by explicitly
            // exiting the program on fatal IOException - see PYIC-8220 and incident INC0014398.
            LOGGER.error("Crashing on UncheckedIOException", e);
            System.exit(1);
            return null;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }

    private int getHttpStatusCodeForErrorResponse(ErrorObject errorObject) {
        return errorObject.getHTTPStatusCode() > 0
                ? errorObject.getHTTPStatusCode()
                : HttpStatusCode.BAD_REQUEST;
    }

    private boolean redirectUrlsDoNotMatch(
            AuthorizationCodeMetadata authorizationCodeMetadata,
            AuthorizationCodeGrant authorizationGrant) {

        if (Objects.isNull(authorizationCodeMetadata.getRedirectUrl())
                && Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return false;
        }

        if (Objects.isNull(authorizationCodeMetadata.getRedirectUrl())
                || Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return true;
        }

        return !authorizationGrant
                .getRedirectionURI()
                .toString()
                .equals(authorizationCodeMetadata.getRedirectUrl());
    }

    private ErrorObject revokeAccessToken(IpvSessionItem ipvSessionItem) {
        try {
            sessionService.revokeAccessToken(ipvSessionItem);
            return OAuth2Error.INVALID_GRANT.setDescription(
                    "Authorization code used too many times");
        } catch (IllegalArgumentException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to revoke access token.", e));
            return OAuth2Error.INVALID_GRANT.setDescription("Failed to revoke access token");
        }
    }
}
