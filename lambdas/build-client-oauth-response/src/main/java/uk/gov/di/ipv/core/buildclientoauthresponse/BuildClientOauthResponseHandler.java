package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientDetails;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.AuthRequestValidator;

import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BuildClientOauthResponseHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final IpvSessionService sessionService;
    private final ConfigurationService configurationService;
    private final AuthRequestValidator authRequestValidator;
    private final AuditService auditService;
    private final String componentId;

    @ExcludeFromGeneratedCoverageReport
    public BuildClientOauthResponseHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new IpvSessionService(configurationService);
        this.authRequestValidator = new AuthRequestValidator(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.componentId =
                configurationService.getSsmParameter(ConfigurationVariable.AUDIENCE_FOR_CLIENTS);
    }

    public BuildClientOauthResponseHandler(
            IpvSessionService sessionService,
            ConfigurationService configurationService,
            AuthRequestValidator authRequestValidator,
            AuditService auditService) {
        this.sessionService = sessionService;
        this.configurationService = configurationService;
        this.authRequestValidator = authRequestValidator;
        this.auditService = auditService;
        this.componentId =
                configurationService.getSsmParameter(ConfigurationVariable.AUDIENCE_FOR_CLIENTS);
    }

    @Override
    @Tracing
    @Logging(clearState = true, logEvent = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {

        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);

            IpvSessionItem ipvSessionItem = sessionService.getIpvSession(ipvSessionId);
            String userId = sessionService.getUserId(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();

            LogHelper.attachClientIdToLogs(clientSessionDetailsDto.getClientId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientSessionDetailsDto.getGovukSigninJourneyId());

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            userId,
                            ipvSessionId,
                            clientSessionDetailsDto.getGovukSigninJourneyId());

            ClientResponse clientResponse;

            if (ipvSessionItem.getErrorCode() != null) {
                clientResponse = generateClientErrorResponse(ipvSessionItem);

            } else {

                Map<String, List<String>> authParameters =
                        getAuthParamsAsMap(ipvSessionItem.getClientSessionDetails());

                var validationResult = authRequestValidator.validateRequest(authParameters);
                if (!validationResult.isValid()) {
                    return StepFunctionHelpers.generateErrorOutputMap(
                            HttpStatus.SC_BAD_REQUEST, validationResult.getError());
                }

                AuthorizationRequest authorizationRequest =
                        AuthorizationRequest.parse(authParameters);
                AuthorizationCode authorizationCode = new AuthorizationCode();

                sessionService.setAuthorizationCode(
                        ipvSessionItem,
                        authorizationCode.getValue(),
                        authorizationRequest.getRedirectionURI().toString());

                clientResponse =
                        generateClientSuccessResponse(ipvSessionItem, authorizationCode.getValue());
            }
            auditService.sendAuditEvent(
                    new AuditEvent(AuditEventTypes.IPV_JOURNEY_END, componentId, auditEventUser));
            Map<String, Object> output = new HashMap<>();
            output.put(
                    "client", Map.of("redirectUrl", clientResponse.getClient().getRedirectUrl()));
            return output;
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.SQS_EXCEPTION);
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to construct redirect uri because: {}", e.getMessage());
            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_CONSTRUCT_REDIRECT_URI);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return StepFunctionHelpers.generateErrorOutputMap(
                    e.getResponseCode(), e.getErrorResponse());
        }
    }

    private ClientResponse generateClientSuccessResponse(
            IpvSessionItem ipvSessionItem, String authorizationCode) throws URISyntaxException {
        URIBuilder redirectUri =
                new URIBuilder(ipvSessionItem.getClientSessionDetails().getRedirectUri())
                        .addParameter("code", authorizationCode);

        if (StringUtils.isNotBlank(ipvSessionItem.getClientSessionDetails().getState())) {
            redirectUri.addParameter("state", ipvSessionItem.getClientSessionDetails().getState());
        }

        return new ClientResponse(new ClientDetails(redirectUri.build().toString()));
    }

    private ClientResponse generateClientErrorResponse(IpvSessionItem ipvSessionItem)
            throws URISyntaxException {
        URIBuilder uriBuilder =
                new URIBuilder(ipvSessionItem.getClientSessionDetails().getRedirectUri());
        uriBuilder.addParameter("error", ipvSessionItem.getErrorCode());
        uriBuilder.addParameter("error_description", ipvSessionItem.getErrorDescription());

        if (StringUtils.isNotBlank(ipvSessionItem.getClientSessionDetails().getState())) {
            uriBuilder.addParameter("state", ipvSessionItem.getClientSessionDetails().getState());
        }

        return new ClientResponse(new ClientDetails(uriBuilder.build().toString()));
    }

    @Tracing
    private Map<String, List<String>> getAuthParamsAsMap(
            ClientSessionDetailsDto clientSessionDetailsDto) {
        if (clientSessionDetailsDto != null) {
            Map<String, List<String>> authParams = new HashMap<>();
            authParams.put(
                    AuthRequestValidator.RESPONSE_TYPE_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getResponseType()));
            authParams.put(
                    AuthRequestValidator.CLIENT_ID_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getClientId()));
            authParams.put(
                    AuthRequestValidator.REDIRECT_URI_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getRedirectUri()));
            authParams.put(
                    AuthRequestValidator.STATE_PARAM,
                    Collections.singletonList(clientSessionDetailsDto.getState()));

            return authParams;
        }

        return Collections.emptyMap();
    }
}
