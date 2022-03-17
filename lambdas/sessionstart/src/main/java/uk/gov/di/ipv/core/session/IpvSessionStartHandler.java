package uk.gov.di.ipv.core.session;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class IpvSessionStartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(IpvSessionStartHandler.class.getName());
    private static final String IPV_SESSION_ID_KEY = "ipvSessionId";
    private static final String RESPONSE_TYPE_PARAM = "response_type";
    private static final String CLIENT_ID_PARAM = "client_id";
    private static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String SCOPE_PARAM = "scope";
    private static final String STATE_PARAM = "state";

    private final ConfigurationService configurationService;

    private final IpvSessionService ipvSessionService;

    @ExcludeFromGeneratedCoverageReport
    public IpvSessionStartHandler() {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    public IpvSessionStartHandler(
            IpvSessionService ipvSessionService, ConfigurationService configurationService) {
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            ClientSessionDetailsDto clientSessionDetails =
                    getClientSessionDetails(input.getQueryStringParameters());

            String ipvSessionId = ipvSessionService.generateIpvSession(clientSessionDetails);

            Map<String, String> response = Map.of(IPV_SESSION_ID_KEY, ipvSessionId);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Ipv session generation failed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }

    private ClientSessionDetailsDto getClientSessionDetails(
            Map<String, String> queryStringParameters) throws HttpResponseExceptionWithErrorBody {
        if (Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty()) {
            LOGGER.warn("Missing client session details in request query parameters");
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }

        String responseType = queryStringParameters.get(RESPONSE_TYPE_PARAM);
        String clientId = queryStringParameters.get(CLIENT_ID_PARAM);
        String redirectUri = queryStringParameters.get(REDIRECT_URI_PARAM);
        String scope = queryStringParameters.get(SCOPE_PARAM);
        String state = queryStringParameters.get(STATE_PARAM);

        Optional<ErrorResponse> error =
                validateClientSessionDetails(responseType, clientId, redirectUri, scope, state);

        if (error.isPresent()) {
            throw new HttpResponseExceptionWithErrorBody(HttpStatus.SC_BAD_REQUEST, error.get());
        }

        return new ClientSessionDetailsDto(responseType, clientId, redirectUri, scope, state);
    }

    private Optional<ErrorResponse> validateClientSessionDetails(
            String responseType, String clientId, String redirectUri, String scope, String state) {
        boolean isInvalid = false;
        if (StringUtils.isBlank(responseType)) {
            LOGGER.warn("Missing response_type query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientId)) {
            LOGGER.warn("Missing client_id query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(redirectUri)) {
            LOGGER.warn("Missing redirect_uri query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(scope)) {
            LOGGER.warn("Missing scope query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(state)) {
            LOGGER.warn("Missing state query parameter");
            isInvalid = true;
        }

        if (isInvalid) {
            return Optional.of(ErrorResponse.MISSING_QUERY_PARAMETERS);
        }
        return Optional.empty();
    }
}
