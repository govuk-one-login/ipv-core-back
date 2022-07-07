package uk.gov.di.ipv.core.library.validation;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public class AuthRequestValidator {

    public static final String RESPONSE_TYPE_PARAM = "response_type";
    public static final String CLIENT_ID_PARAM = "client_id";
    public static final String REDIRECT_URI_PARAM = "redirect_uri";
    public static final String STATE_PARAM = "state";
    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigurationService configurationService;

    public AuthRequestValidator(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public ValidationResult validateRequest(
            Map<String, List<String>> queryStringParameters, Map<String, String> requestHeaders) {
        if (queryStringParamsMissing(queryStringParameters)) {
            LOGGER.error("Missing required query parameters for authorisation request");
            return new ValidationResult(false);
        }

        if (sessionIdMissing(requestHeaders)) {
            LOGGER.error("Missing IPV session ID from headers");
            return new ValidationResult(false);
        }

        var valid = validateRedirectUrl(queryStringParameters);
        return valid ? ValidationResult.createValidResult() : new ValidationResult(false);
    }

    private boolean queryStringParamsMissing(Map<String, List<String>> queryStringParameters) {
        return Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty();
    }

    private boolean sessionIdMissing(Map<String, String> requestHeaders) {
        return StringUtils.isBlank(
                RequestHelper.getHeaderByKey(requestHeaders, IPV_SESSION_ID_HEADER_KEY));
    }

    private boolean validateRedirectUrl(Map<String, List<String>> queryStringParameters) {
        try {
            String redirectUrl =
                    getOnlyValueOrThrow(
                            queryStringParameters.getOrDefault(REDIRECT_URI_PARAM, List.of()));
            String clientId =
                    getOnlyValueOrThrow(
                            queryStringParameters.getOrDefault(CLIENT_ID_PARAM, List.of()));
            List<String> clientRedirectUrls = configurationService.getClientRedirectUrls(clientId);

            if (!clientRedirectUrls.contains(redirectUrl)) {
                LOGGER.error("Invalid redirect URL for client_id {}: '{}'", clientId, redirectUrl);
                return false;
            }
            return true;
        } catch (IllegalArgumentException e) {
            LOGGER.error(e.getMessage());
            return false;
        }
    }

    private String getOnlyValueOrThrow(List<String> container) {
        if (container.size() != 1) {
            throw new IllegalArgumentException(
                    String.format("Parameter must have exactly one value: %s", container));
        }
        return container.get(0);
    }
}
