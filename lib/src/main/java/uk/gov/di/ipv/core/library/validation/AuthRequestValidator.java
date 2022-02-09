package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class AuthRequestValidator {

    public static final String CLIENT_ID_PARAM = "client_id";
    public static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthRequestValidator.class);

    private final ConfigurationService configurationService;

    public AuthRequestValidator(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public ValidationResult<ErrorResponse> validateRequest(
            Map<String, List<String>> queryStringParameters, Map<String, String> requestHeaders) {
        if (queryStringParamsMissing(queryStringParameters)) {
            LOGGER.error("Missing required query parameters for authorisation request");
            return new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }

        if (sessionIdMissing(requestHeaders)) {
            LOGGER.error("Missing IPV session ID from headers");
            return new ValidationResult<>(false, ErrorResponse.MISSING_IPV_SESSION_ID);
        }

        if (unableToParseQueryStrings(queryStringParameters)) {
            return new ValidationResult<>(
                    false, ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }

        var errorResult = validateRedirectUrl(queryStringParameters);
        if (errorResult.isPresent()) {
            return new ValidationResult<>(false, errorResult.get());
        }

        return ValidationResult.createValidResult();
    }

    private boolean queryStringParamsMissing(Map<String, List<String>> queryStringParameters) {
        return Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty();
    }

    private boolean sessionIdMissing(Map<String, String> requestHeaders) {
        return StringUtils.isBlank(
                RequestHelper.getHeaderByKey(requestHeaders, IPV_SESSION_ID_HEADER_KEY));
    }

    private boolean unableToParseQueryStrings(Map<String, List<String>> queryStringParameters) {
        try {
            AuthenticationRequest.parse(queryStringParameters);
            LOGGER.info("Successfully parsed authentication request");
            return false;
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return true;
        }
    }

    private Optional<ErrorResponse> validateRedirectUrl(
            Map<String, List<String>> queryStringParameters) {
        try {
            String redirectUrl = getOnlyValueOrThrow(queryStringParameters.get(REDIRECT_URI_PARAM));
            String clientId = getOnlyValueOrThrow(queryStringParameters.get(CLIENT_ID_PARAM));
            List<String> clientRedirectUrls = configurationService.getClientRedirectUrls(clientId);

            if (!clientRedirectUrls.contains(redirectUrl)) {
                LOGGER.error("Invalid redirect URL for client_id {}: '{}'", clientId, redirectUrl);
                return Optional.of(ErrorResponse.INVALID_REDIRECT_URL);
            }
            return Optional.empty();
        } catch (IllegalArgumentException e) {
            LOGGER.error(e.getMessage());
            return Optional.of(ErrorResponse.INVALID_REQUEST_PARAM);
        }
    }

    private String getOnlyValueOrThrow(List<String> container) {
        if (container.size() != 1) {
            throw new IllegalArgumentException(
                    String.format("Container must have exactly one element: %s", container));
        }
        return container.get(0);
    }
}
