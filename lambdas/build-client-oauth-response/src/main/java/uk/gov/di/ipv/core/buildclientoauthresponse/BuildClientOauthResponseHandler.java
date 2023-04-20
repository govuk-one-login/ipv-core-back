package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
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

/**
 * Lambda called when the user has completed their user journey in IPV Core
 */
public class BuildClientOauthResponseHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final IpvSessionService sessionService;
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionService;
    private final AuthRequestValidator authRequestValidator;
    private final AuditService auditService;
    private final String componentId;
    private static final ObjectMapper mapper = new ObjectMapper();

    @SuppressWarnings("unused") // Used by AWS
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
    public Map<String, Object> handleRequest(
            Map<String, String> input, Context context) {

        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            String ipAddress = StepFunctionHelpers.getIpAddress(input);
            IpvSessionItem ipvSessionItem = sessionService.getIpvSession(ipvSessionId);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

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

                var validationResult =
                        authRequestValidator.validateRequest(authParameters, input);
                if (!validationResult.isValid()) {
                    return StepFunctionHelpers.generateErrorOutputMap(HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_QUERY_PARAMETERS);
                }

                AuthorizationRequest authorizationRequest =
                        AuthorizationRequest.parse(authParameters);
                AuthorizationCode authorizationCode = new AuthorizationCode();

                sessionService.setAuthorizationCode(
                        ipvSessionItem,
                        authorizationCode.getValue(),
                        authorizationRequest.getRedirectionURI().toString());

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

            return mapper.convertValue(clientResponse, Map.class);
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT);
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to construct redirect uri because: {}", e.getMessage());
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_BUILD_REDIRECT_RESPONSE
            );
        } catch (HttpResponseExceptionWithErrorBody e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    e.getResponseCode(), e.getErrorResponse());
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
