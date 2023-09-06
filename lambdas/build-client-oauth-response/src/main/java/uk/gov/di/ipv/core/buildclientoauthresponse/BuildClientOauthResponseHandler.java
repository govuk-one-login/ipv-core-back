package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
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
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator.CLIENT_SESSION_ID_HEADER_KEY;
import static uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator.IPV_SESSION_ID_HEADER_KEY;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CLIENT_OAUTH_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_REDIRECT_URI;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getClientOAuthSessionId;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getFeatureSet;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionIdAllowNull;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

public class BuildClientOauthResponseHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final IpvSessionService sessionService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final AuthRequestValidator authRequestValidator;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public BuildClientOauthResponseHandler() {
        this.configService = new ConfigService();
        this.sessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.authRequestValidator = new AuthRequestValidator(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
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
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest input, Context context) {

        LogHelper.attachComponentIdToLogs(configService);

        try {
            String ipvSessionId = getIpvSessionIdAllowNull(input);
            String ipAddress = getIpAddress(input);
            String clientSessionId = getClientOAuthSessionId(input);
            String featureSet = getFeatureSet(input);
            configService.setFeatureSet(featureSet);

            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);

            IpvSessionItem ipvSessionItem;
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
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "No ipvSession for existing ClientOAuthSession.")
                                .with(LOG_CLIENT_OAUTH_SESSION_ID.getFieldName(), clientSessionId);
                LOGGER.info(mapMessage);
                return generateClientOAuthSessionErrorResponse(clientOAuthSessionItem)
                        .toObjectMap();
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

            if (ipvSessionItem.getErrorCode() != null) {
                clientResponse =
                        generateClientErrorResponse(ipvSessionItem, clientOAuthSessionItem);
            } else {
                Map<String, List<String>> authParameters =
                        getAuthParamsAsMap(clientOAuthSessionItem);
                Map<String, String> params = new HashMap<>();
                params.put(IPV_SESSION_ID_HEADER_KEY, ipvSessionId);
                params.put(CLIENT_SESSION_ID_HEADER_KEY, clientSessionId);
                var validationResult = authRequestValidator.validateRequest(authParameters, params);
                if (!validationResult.isValid()) {
                    return new JourneyErrorResponse(
                                    null, HttpStatus.SC_BAD_REQUEST, validationResult.getError())
                            .toObjectMap();
                }

                AuthorizationCode authorizationCode = new AuthorizationCode();
                AuthorizationRequest authorizationRequest =
                        AuthorizationRequest.parse(authParameters);
                sessionService.setAuthorizationCode(
                        ipvSessionItem,
                        authorizationCode.getValue(),
                        authorizationRequest.getRedirectionURI().toString());

                clientResponse =
                        generateClientSuccessResponse(
                                clientOAuthSessionItem, authorizationCode.getValue());
            }
            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_JOURNEY_END,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser));

            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_LAMBDA_RESULT.getFieldName(),
                                    "Successfully generated ipv client oauth response.")
                            .with(
                                    LOG_REDIRECT_URI.getFieldName(),
                                    clientResponse.getClient().getRedirectUrl());
            LOGGER.info(message);

            return clientResponse.toObjectMap();
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_BAD_REQUEST,
                            ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS)
                    .toObjectMap();
        } catch (SqsException e) {
            LogHelper.logErrorMessage("Failed to send audit event to SQS queue.", e.getMessage());
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT,
                            e.getMessage())
                    .toObjectMap();
        } catch (URISyntaxException e) {
            LogHelper.logErrorMessage("Failed to construct redirect uri.", e.getMessage());
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_CONSTRUCT_REDIRECT_URI,
                            e.getMessage())
                    .toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
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

    private ClientResponse generateClientOAuthSessionErrorResponse(
            ClientOAuthSessionItem clientOAuthSessionItem) throws URISyntaxException {
        URIBuilder uriBuilder = new URIBuilder(clientOAuthSessionItem.getRedirectUri());
        uriBuilder.addParameter("error", OAuth2Error.ACCESS_DENIED.getCode());
        uriBuilder.addParameter("error_description", "Missing Context");

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
