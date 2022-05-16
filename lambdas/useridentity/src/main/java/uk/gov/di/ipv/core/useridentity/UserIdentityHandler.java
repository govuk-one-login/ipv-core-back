package uk.gov.di.ipv.core.useridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AccessTokenService;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

public class UserIdentityHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserIdentityHandler.class);
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    private final UserIdentityService userIdentityService;
    private final AccessTokenService accessTokenService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;

    public UserIdentityHandler(
            UserIdentityService userIdentityService,
            AccessTokenService accessTokenService,
            ConfigurationService configurationService,
            AuditService auditService) {
        this.userIdentityService = userIdentityService;
        this.accessTokenService = accessTokenService;
        this.configurationService = configurationService;
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public UserIdentityHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.accessTokenService = new AccessTokenService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            String accessTokenString =
                    RequestHelper.getHeaderByKey(input.getHeaders(), AUTHORIZATION_HEADER_KEY);

            // Performs validation on header value and throws a ParseException if invalid
            AccessToken.parse(accessTokenString);

            String ipvSessionId =
                    accessTokenService.getIpvSessionIdByAccessToken(accessTokenString);

            if (StringUtils.isBlank(ipvSessionId)) {
                LOGGER.error(
                        "User credential could not be retrieved. The supplied access token was not found in the database.");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                        OAuth2Error.ACCESS_DENIED
                                .appendDescription(
                                        " - The supplied access token was not found in the database")
                                .toJSONObject());
            }

            UserIdentity userIdentity = userIdentityService.getUserIssuedCredentials(ipvSessionId);

            auditService.sendAuditEvent(AuditEventTypes.IPV_IDENTITY_ISSUED);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HTTPResponse.SC_OK, userIdentity);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
}
