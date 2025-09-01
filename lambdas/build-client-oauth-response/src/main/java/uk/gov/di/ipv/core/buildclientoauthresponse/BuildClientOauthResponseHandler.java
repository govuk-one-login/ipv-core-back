package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientDetails;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionAccountIntervention;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator.CLIENT_SESSION_ID_HEADER_KEY;
import static uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator.IPV_SESSION_ID_HEADER_KEY;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CLIENT_OAUTH_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_REDIRECT_URI;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getClientOAuthSessionIdAllowMissing;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getFeatureSet;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionIdAllowMissing;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;

public class BuildClientOauthResponseHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String STATE = "state";

    private final IpvSessionService sessionService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final AuthRequestValidator authRequestValidator;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public BuildClientOauthResponseHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildClientOauthResponseHandler(ConfigService configService) {
        this.configService = configService;
        this.sessionService = new IpvSessionService(configService);
        this.clientOAuthSessionService = new ClientOAuthSessionDetailsService(configService);
        this.authRequestValidator = new AuthRequestValidator(configService);
        this.auditService = AuditService.create(configService);
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
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Object> handleRequest(JourneyRequest input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            var ipvSessionId = getIpvSessionIdAllowMissing(input);
            var ipAddress = getIpAddress(input);
            var clientSessionId = getClientOAuthSessionIdAllowMissing(input);
            var featureSet = getFeatureSet(input);
            configService.setFeatureSet(featureSet);

            IpvSessionItem ipvSessionItem;
            ClientOAuthSessionItem clientOAuthSessionItem;
            if (ipvSessionId != null) {
                ipvSessionItem = sessionService.getIpvSession(ipvSessionId);
                clientOAuthSessionItem =
                        clientOAuthSessionService.getClientOAuthSession(
                                ipvSessionItem.getClientOAuthSessionId());
            } else if (clientSessionId != null) {
                clientOAuthSessionItem =
                        clientOAuthSessionService.getClientOAuthSession(clientSessionId);
                LOGGER.warn(
                        LogHelper.buildLogMessage("No ipvSession for existing ClientOAuthSession.")
                                .with(LOG_CLIENT_OAUTH_SESSION_ID.getFieldName(), clientSessionId));
                return generateClientOAuthSessionErrorResponse(clientOAuthSessionItem)
                        .toObjectMap();
            } else {
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatusCode.BAD_REQUEST, ErrorResponse.MISSING_SESSION_ID);
            }

            ipvSessionItem.setFeatureSetFromList(featureSet);
            sessionService.updateIpvSession(ipvSessionItem);

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
                                    null, HttpStatusCode.BAD_REQUEST, validationResult.getError())
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
                    AuditEvent.createWithDeviceInformation(
                            AuditEventTypes.IPV_JOURNEY_END,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            new AuditRestrictedDeviceInformation(input.getDeviceInformation())));

            EmbeddedMetricHelper.identityJourneyComplete();

            var isReproveIdentity = clientOAuthSessionItem.getReproveIdentity();
            if (Boolean.TRUE.equals(isReproveIdentity)) {
                Vot sesssionVot = ipvSessionItem.getVot();
                List<Vot> vtrVots = clientOAuthSessionItem.getVtrAsVots();
                auditService.sendAuditEvent(
                        AuditEvent.createWithoutDeviceInformation(
                                AuditEventTypes.IPV_ACCOUNT_INTERVENTION_END,
                                configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser,
                                AuditExtensionAccountIntervention.newReproveIdentity(
                                        ipvSessionItem.getErrorCode() == null
                                                && vtrVots.contains(sesssionVot))));
            }

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
            LOGGER.error(
                    LogHelper.buildErrorMessage("Authentication request could not be parsed", e));
            return buildJourneyErrorResponse(
                    HttpStatusCode.BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        } catch (URISyntaxException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to construct redirect uri.", e));
            return buildJourneyErrorResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_CONSTRUCT_REDIRECT_URI);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            return buildJourneyErrorResponse(
                    HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.IPV_SESSION_NOT_FOUND);
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

    private Map<String, Object> buildJourneyErrorResponse(
            int statusCode, ErrorResponse errorResponse) {
        return new JourneyErrorResponse(JOURNEY_ERROR_PATH, statusCode, errorResponse)
                .toObjectMap();
    }

    private ClientResponse generateClientSuccessResponse(
            ClientOAuthSessionItem clientOAuthSessionItem, String authorizationCode)
            throws URISyntaxException {
        URIBuilder redirectUri =
                new URIBuilder(clientOAuthSessionItem.getRedirectUri())
                        .addParameter("code", authorizationCode);

        if (StringUtils.isNotBlank(clientOAuthSessionItem.getState())) {
            redirectUri.addParameter(STATE, clientOAuthSessionItem.getState());
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
            uriBuilder.addParameter(STATE, clientOAuthSessionItem.getState());
        }

        return new ClientResponse(new ClientDetails(uriBuilder.build().toString()));
    }

    private ClientResponse generateClientOAuthSessionErrorResponse(
            ClientOAuthSessionItem clientOAuthSessionItem) throws URISyntaxException {
        URIBuilder uriBuilder = new URIBuilder(clientOAuthSessionItem.getRedirectUri());
        uriBuilder.addParameter("error", OAuth2Error.ACCESS_DENIED.getCode());
        uriBuilder.addParameter("error_description", "Missing Context");

        if (StringUtils.isNotBlank(clientOAuthSessionItem.getState())) {
            uriBuilder.addParameter(STATE, clientOAuthSessionItem.getState());
        }

        return new ClientResponse(new ClientDetails(uriBuilder.build().toString()));
    }

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
