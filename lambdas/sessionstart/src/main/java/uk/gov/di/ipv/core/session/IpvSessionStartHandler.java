package uk.gov.di.ipv.core.session;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;
import java.util.Optional;

public class IpvSessionStartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(IpvSessionStartHandler.class.getName());
    private static final String IPV_SESSION_ID_KEY = "ipvSessionId";

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
            ObjectMapper objectMapper = new ObjectMapper();
            ClientSessionDetailsDto clientSessionDetails =
                    objectMapper.readValue(input.getBody(), ClientSessionDetailsDto.class);

            Optional<ErrorResponse> error = validateClientSessionDetails(clientSessionDetails);

            if (error.isPresent()) {
                LOGGER.error(
                        "Failed to parse the request body into a ClientSessionDetailsDto object");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, error.get());
            }

            String ipvSessionId = ipvSessionService.generateIpvSession(clientSessionDetails);

            Map<String, String> response = Map.of(IPV_SESSION_ID_KEY, ipvSessionId);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
        } catch (IllegalArgumentException | JsonProcessingException e) {
            LOGGER.error(
                    "Failed to parse the request body into a ClientSessionDetailsDto object", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_SESSION_REQUEST);
        }
    }

    private Optional<ErrorResponse> validateClientSessionDetails(
            ClientSessionDetailsDto clientSessionDetailsDto) {
        boolean isInvalid = false;
        if (StringUtils.isBlank(clientSessionDetailsDto.getResponseType())) {
            LOGGER.warn("Missing response_type query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getClientId())) {
            LOGGER.warn("Missing client_id query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getRedirectUri())) {
            LOGGER.warn("Missing redirect_uri query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getScope())) {
            LOGGER.warn("Missing scope query parameter");
            isInvalid = true;
        }

        if (StringUtils.isBlank(clientSessionDetailsDto.getState())) {
            LOGGER.warn("Missing state query parameter");
            isInvalid = true;
        }

        if (isInvalid) {
            return Optional.of(ErrorResponse.INVALID_SESSION_REQUEST);
        }
        return Optional.empty();
    }
}
