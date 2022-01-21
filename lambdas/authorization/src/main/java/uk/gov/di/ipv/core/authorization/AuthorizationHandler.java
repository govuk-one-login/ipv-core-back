package uk.gov.di.ipv.core.authorization;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class AuthorizationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationHandler.class);

    private final AuthorizationCodeService authorizationCodeService;

    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationHandler() {
        this.configurationService = new ConfigurationService();
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
    }

    public AuthorizationHandler(
            AuthorizationCodeService authorizationCodeService,
            ConfigurationService configurationService) {
        this.authorizationCodeService = authorizationCodeService;
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Map<String, List<String>> queryStringParameters = getQueryStringParametersAsMap(input);

        try {
            ValidationResult<ErrorResponse> validationResult =
                    validateRequest(queryStringParameters, input.getHeaders());
            if (!validationResult.isValid()) {
                LOGGER.error("Missing required query parameters for authorisation request");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, validationResult.getError());
            }
            AuthenticationRequest.parse(queryStringParameters);
            LOGGER.info("Successfully parsed authentication request");
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }

        AuthorizationCode authorizationCode = authorizationCodeService.generateAuthorizationCode();

        String ipvSessionId =
                RequestHelper.getHeaderByKey(input.getHeaders(), IPV_SESSION_ID_HEADER_KEY);

        authorizationCodeService.persistAuthorizationCode(
                authorizationCode.getValue(), ipvSessionId);

        Map<String, Identifier> payload = Map.of("code", authorizationCode);

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, payload);
    }

    private Map<String, List<String>> getQueryStringParametersAsMap(
            APIGatewayProxyRequestEvent input) {
        if (input.getQueryStringParameters() != null) {
            return input.getQueryStringParameters().entrySet().stream()
                    .collect(
                            Collectors.toMap(
                                    Map.Entry::getKey, entry -> List.of(entry.getValue())));
        }
        return Collections.emptyMap();
    }

    private ValidationResult<ErrorResponse> validateRequest(
            Map<String, List<String>> queryStringParameters, Map<String, String> requestHeaders) {
        if (Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty()) {
            return new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }

        String ipvSessionId =
                RequestHelper.getHeaderByKey(requestHeaders, IPV_SESSION_ID_HEADER_KEY);
        if (StringUtils.isBlank(ipvSessionId)) {
            return new ValidationResult<>(false, ErrorResponse.MISSING_IPV_SESSION_ID);
        }
        return ValidationResult.createValidResult();
    }
}
