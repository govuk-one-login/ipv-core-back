package uk.gov.di.ipv.core.authorization;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
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
import uk.gov.di.ipv.core.library.validation.AuthRequestValidator;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AuthorizationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationHandler.class);
    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";

    private final AuthorizationCodeService authorizationCodeService;
    private final ConfigurationService configurationService;
    private final AuthRequestValidator authRequestValidator;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationHandler() {
        this.configurationService = new ConfigurationService();
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.authRequestValidator = new AuthRequestValidator(configurationService);
    }

    public AuthorizationHandler(
            AuthorizationCodeService authorizationCodeService,
            ConfigurationService configurationService,
            AuthRequestValidator authRequestValidator) {
        this.authorizationCodeService = authorizationCodeService;
        this.configurationService = configurationService;
        this.authRequestValidator = authRequestValidator;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Map<String, List<String>> queryStringParameters = getQueryStringParametersAsMap(input);

        var validationResult =
                authRequestValidator.validateRequest(queryStringParameters, input.getHeaders());
        if (!validationResult.isValid()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, validationResult.getError());
        }

        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest = AuthenticationRequest.parse(queryStringParameters);
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
                authorizationCode.getValue(),
                ipvSessionId,
                authenticationRequest.getRedirectionURI().toString());

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
}
