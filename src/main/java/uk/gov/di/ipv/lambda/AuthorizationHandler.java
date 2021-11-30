package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.service.AuthorizationCodeService;
import uk.gov.di.ipv.validation.ValidationResult;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class AuthorizationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>  {

    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationHandler.class);

    private final AuthorizationCodeService authorizationCodeService;

    public AuthorizationHandler() {
        this.authorizationCodeService = new AuthorizationCodeService();
    }

    public AuthorizationHandler(AuthorizationCodeService authorizationCodeService) {
        this.authorizationCodeService = authorizationCodeService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        Map<String, List<String>> queryStringParameters = getQueryStringParametersAsMap(input);

        try {
            ValidationResult validationResult = validateRequest(queryStringParameters, input.getHeaders());
            if (!validationResult.isValid()) {
                LOGGER.error("Missing required query parameters for authorisation request");
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, validationResult.getError());
            }
            AuthenticationRequest.parse(queryStringParameters);
            LOGGER.info("Successfully parsed authentication request");
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }

        AuthorizationCode authorizationCode = authorizationCodeService.generateAuthorizationCode();

        String ipvSessionId = input.getHeaders().get(IPV_SESSION_ID_HEADER_KEY);
        authorizationCodeService.persistAuthorizationCode(authorizationCode.getValue(),ipvSessionId);

        Map<String, Identifier> payload = Map.of("code", authorizationCode);

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, payload);
    }

    private Map<String, List<String>> getQueryStringParametersAsMap(APIGatewayProxyRequestEvent input) {
        if (input.getQueryStringParameters() != null) {
            return input.getQueryStringParameters().entrySet().stream()
                    .collect(Collectors.toMap(Map.Entry::getKey, entry -> List.of(entry.getValue())));
        }
        return Collections.emptyMap();
    }

    private ValidationResult validateRequest(Map<String, List<String>> queryStringParameters, Map<String, String> requestHeaders) {
        if (Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty()) {
            return new ValidationResult(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }

        if (!requestHeaders.containsKey(IPV_SESSION_ID_HEADER_KEY)) {
            return new ValidationResult(false, ErrorResponse.MISSING_IPV_SESSION_ID);
        }
        return ValidationResult.createValidResult();
    }
}
