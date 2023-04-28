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
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.issueclientaccesstoken.exception.ClientAuthenticationException;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.AccessTokenService;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.issueclientaccesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

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
        this.configService = new ConfigService();
        this.accessTokenService = new AccessTokenService(configService);
        this.sessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.tokenRequestValidator =
                new TokenRequestValidator(configService, new ClientAuthJwtIdService(configService));
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            tokenRequestValidator.authenticateClient(input.getBody());

            AuthorizationCodeGrant authorizationGrant =
                    (AuthorizationCodeGrant)
                            AuthorizationGrant.parse(URLUtils.parseParameters(input.getBody()));
            ValidationResult<ErrorObject> validationResult =
                    accessTokenService.validateAuthorizationGrant(authorizationGrant);
            if (!validationResult.isValid()) {
                ErrorObject error = validationResult.getError();
                LogHelper.logOauthError(
                        "Invalid auth grant received.", error.getCode(), error.getDescription());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        getHttpStatusCodeForErrorResponse(validationResult.getError()),
                        validationResult.getError().toJSONObject());
            }

            IpvSessionItem ipvSessionItem =
                    sessionService
                            .getIpvSessionByAuthorizationCode(
                                    authorizationGrant.getAuthorizationCode().getValue())
                            .orElseThrow();
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            LogHelper.attachIpvSessionIdToLogs(ipvSessionItem.getIpvSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            if (ipvSessionItem.getAccessToken() != null) {
                ErrorObject error = revokeAccessToken(ipvSessionItem);
                LogHelper.logOauthError(
                        "Auth code has been used multiple times",
                        error.getCode(),
                        error.getDescription());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            AuthorizationCodeMetadata authorizationCodeMetadata =
                    ipvSessionItem.getAuthorizationCodeMetadata();

            if (authorizationCodeMetadata.isExpired(
                    Long.parseLong(
                            configService.getSsmParameter(
                                    ConfigurationVariable.AUTH_CODE_EXPIRY_SECONDS)))) {
                ErrorObject error =
                        OAuth2Error.INVALID_GRANT.setDescription("Authorization code expired");
                LogHelper.logOauthError(
                        String.format(
                                "Access Token could not be issued. The supplied authorization code has expired. Created at: %s",
                                ipvSessionItem
                                        .getAuthorizationCodeMetadata()
                                        .getCreationDateTime()),
                        error.getCode(),
                        error.getDescription());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            if (redirectUrlsDoNotMatch(authorizationCodeMetadata, authorizationGrant)) {
                ErrorObject error =
                        OAuth2Error.INVALID_GRANT.setDescription(
                                "Redirect URL in token request does not match redirect URL received in auth code request");

                LogHelper.logOauthError(
                        String.format(
                                "Invalid redirect URL value received. Session ID: %s",
                                ipvSessionItem.getIpvSessionId()),
                        error.getCode(),
                        error.getDescription());

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
                    HttpStatus.SC_OK, accessTokenResponse.toJSONObject());
        } catch (ParseException e) {
            LogHelper.logOauthError(
                    "Token request could not be parsed",
                    e.getErrorObject().getCode(),
                    e.getErrorObject().getDescription());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    getHttpStatusCodeForErrorResponse(e.getErrorObject()),
                    e.getErrorObject().toJSONObject());
        } catch (NoSuchElementException e) {
            ErrorObject error =
                    OAuth2Error.INVALID_GRANT.setDescription(
                            "The supplied authorization code was not found in the database");

            LogHelper.logOauthError(
                    "Access Token could not be issued", error.getCode(), error.getDescription());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    error.getHTTPStatusCode(), error.toJSONObject());
        } catch (ClientAuthenticationException e) {
            ErrorObject error = OAuth2Error.INVALID_CLIENT.setDescription(e.getMessage());

            LogHelper.logOauthError(
                    "Client authentication failed", error.getCode(), error.getDescription());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    error.getHTTPStatusCode(), error.toJSONObject());
        }
    }

    @Tracing
    private int getHttpStatusCodeForErrorResponse(ErrorObject errorObject) {
        return errorObject.getHTTPStatusCode() > 0
                ? errorObject.getHTTPStatusCode()
                : HttpStatus.SC_BAD_REQUEST;
    }

    @Tracing
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
            LogHelper.logErrorMessage("Failed to revoke access token.", e.getMessage());
            return OAuth2Error.INVALID_GRANT.setDescription("Failed to revoke access token");
        }
    }
}
