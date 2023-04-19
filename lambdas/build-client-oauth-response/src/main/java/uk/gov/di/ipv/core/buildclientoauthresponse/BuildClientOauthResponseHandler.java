package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientDetails;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.*;

import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BuildClientOauthResponseHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final IpvSessionService sessionService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final AuthRequestValidator authRequestValidator;
    private final AuditService auditService;
    private final String componentId;

    @ExcludeFromGeneratedCoverageReport
    public BuildClientOauthResponseHandler() {
        this.configService = new ConfigService();
        this.sessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.authRequestValidator = new AuthRequestValidator(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
    }

    public BuildClientOauthResponseHandler(
            IpvSessionService sessionService,
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionService,
            AuthRequestValidator authRequestValidator,
            AuditService auditService) {
        this.sessionService = sessionService;
        this.configService = configService;
        this.clientOAuthSessionService = clientOAuthSessionService;
        this.authRequestValidator = authRequestValidator;
        this.auditService = auditService;
        this.componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = RequestHelper.getIpvSessionIdAllowNull(input);
            String clientSessionId = RequestHelper.getClientOAuthSessionId(input);
            String ipAddress = RequestHelper.getIpAddress(input);

            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);

            IpvSessionItem ipvSessionItem = null;
            ClientOAuthSessionItem clientOAuthSessionItem;
            if (!StringUtils.isBlank(ipvSessionId)) {
                ipvSessionItem = sessionService.getIpvSession(ipvSessionId);
                clientOAuthSessionItem =
                        clientOAuthSessionService.getClientOAuthSession(
                                ipvSessionItem.getClientOAuthSessionId());
            } else if (!StringUtils.isBlank(clientSessionId)) {
                clientOAuthSessionItem =
                        clientOAuthSessionService.getClientOAuthSession(clientSessionId);
                var mapMessage =
                        new StringMapMessage()
                                .with("message", "No ipvSession for existing ClientOAuthSession")
                                .with("clientOAuthSessionId", clientSessionId);
                LOGGER.info(mapMessage);
                // We don't have ipvSession here.....should we generate a IPVSession here with this
                // clientSessionId and then update its auth code below
            } else {
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_SESSION_ID);
            }

            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);
            LogHelper.attachClientSessionIdToLogs(clientOAuthSessionItem.getClientOAuthSessionId());
            LogHelper.attachClientIdToLogs(clientOAuthSessionItem.getClientId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            clientOAuthSessionItem.getUserId(),
                            ipvSessionId,
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            ipAddress);

            ClientResponse clientResponse;

            if (ipvSessionItem != null && ipvSessionItem.getErrorCode() != null) {
                clientResponse =
                        generateClientErrorResponse(ipvSessionItem, clientOAuthSessionItem);
            } else {
                Map<String, List<String>> authParameters =
                        getAuthParamsAsMap(clientOAuthSessionItem);

                var validationResult =
                        authRequestValidator.validateRequest(authParameters, input.getHeaders());
                if (!validationResult.isValid()) {
                    return ApiGatewayResponseGenerator.proxyJsonResponse(
                            HttpStatus.SC_BAD_REQUEST, validationResult.getError());
                }

                AuthorizationCode authorizationCode = new AuthorizationCode();
                if (ipvSessionItem != null) {
                    AuthorizationRequest authorizationRequest =
                            AuthorizationRequest.parse(authParameters);
                    sessionService.setAuthorizationCode(
                            ipvSessionItem,
                            authorizationCode.getValue(),
                            authorizationRequest.getRedirectionURI().toString());
                }

                clientResponse =
                        generateClientSuccessResponse(
                                clientOAuthSessionItem, authorizationCode.getValue());
            }
            auditService.sendAuditEvent(
                    new AuditEvent(AuditEventTypes.IPV_JOURNEY_END, componentId, auditEventUser));

            var message =
                    new StringMapMessage()
                            .with(
                                    "lambdaResult",
                                    "Successfully generated ipv client oauth response.")
                            .with("redirectUri", clientResponse.getClient().getRedirectUrl());
            LOGGER.info(message);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, clientResponse);
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to construct redirect uri because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }

    private ClientResponse generateClientSuccessResponse(
            ClientOAuthSessionItem clientOAuthSessionItem, String authorizationCode)
            throws URISyntaxException {
        URIBuilder redirectUri =
                new URIBuilder(clientOAuthSessionItem.getRedirectUri())
                        .addParameter("code", authorizationCode);

        if (StringUtils.isNotBlank(clientOAuthSessionItem.getState())) {
            redirectUri.addParameter("state", clientOAuthSessionItem.getState());
        }

        return new ClientResponse(new ClientDetails(redirectUri.build().toString()));
    }

    private ClientResponse generateClientErrorResponse(
            IpvSessionItem ipvSessionItem, ClientOAuthSessionItem clientOAuthSessionItem)
            throws URISyntaxException {
        URIBuilder uriBuilder = new URIBuilder(clientOAuthSessionItem.getRedirectUri());
        uriBuilder.addParameter("error", ipvSessionItem.getErrorCode());
        uriBuilder.addParameter("error_description", ipvSessionItem.getErrorDescription());

        if (StringUtils.isNotBlank(clientOAuthSessionItem.getState())) {
            uriBuilder.addParameter("state", clientOAuthSessionItem.getState());
        }

        return new ClientResponse(new ClientDetails(uriBuilder.build().toString()));
    }

    @Tracing
    private Map<String, List<String>> getAuthParamsAsMap(
            ClientOAuthSessionItem clientOAuthSessionItem) {
        if (clientOAuthSessionItem != null) {
            Map<String, List<String>> authParams = new HashMap<>();
            authParams.put(
                    AuthRequestValidator.RESPONSE_TYPE_PARAM,
                    Collections.singletonList(clientOAuthSessionItem.getResponseType()));
            authParams.put(
                    AuthRequestValidator.CLIENT_ID_PARAM,
                    Collections.singletonList(clientOAuthSessionItem.getClientId()));
            authParams.put(
                    AuthRequestValidator.REDIRECT_URI_PARAM,
                    Collections.singletonList(clientOAuthSessionItem.getRedirectUri()));
            authParams.put(
                    AuthRequestValidator.STATE_PARAM,
                    Collections.singletonList(clientOAuthSessionItem.getState()));

            return authParams;
        }

        return Collections.emptyMap();
    }
}
