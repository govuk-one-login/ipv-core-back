package uk.gov.di.ipv.core.authorization;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.Identifier;
import org.apache.http.HttpStatus;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
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
}
