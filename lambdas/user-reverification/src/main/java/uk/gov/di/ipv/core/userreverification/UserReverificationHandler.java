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
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.builduseridentity.UserIdentityRequestHandler;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
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
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;

public class UserReverificationHandler extends UserIdentityRequestHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final ReverificationFailureCode DEFAULT_FAILURE_CODE =
            ReverificationFailureCode.IDENTITY_CHECK_INCOMPLETE;
    private static final String DEFAULT_FAILURE_MESSAGE = "Unable to complete identity check.";

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
    }

    @ExcludeFromGeneratedCoverageReport
    public UserReverificationHandler() {
        super(REVERIFICATION);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

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
                var failureDesc =
                        ipvSessionItem.getFailureDescription() != null
                                ? ipvSessionItem.getFailureDescription()
                                : DEFAULT_FAILURE_MESSAGE;

                response = ReverificationResponse.failureResponse(userId, failureCode, failureDesc);
            }
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
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }
}
