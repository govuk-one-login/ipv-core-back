package uk.gov.di.ipv.core.buildclientoauthresponse.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.utils.StringUtils;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CLIENT_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_REDIRECT_URI;

public class AuthRequestValidator {

    public static final String RESPONSE_TYPE_PARAM = "response_type";
    public static final String CLIENT_ID_PARAM = "client_id";
    public static final String REDIRECT_URI_PARAM = "redirect_uri";
    public static final String STATE_PARAM = "state";
    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    public static final String CLIENT_SESSION_ID_HEADER_KEY = "client-session-id";
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;

    public AuthRequestValidator(ConfigService configService) {
        this.configService = configService;
    }

    public ValidationResult<ErrorResponse> validateRequest(
            Map<String, List<String>> queryStringParameters, Map<String, String> requestHeaders) {
        if (queryStringParamsMissing(queryStringParameters)) {
            LOGGER.error("Missing required query parameters for authorisation request");
            return new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }

        if (sessionIdMissing(requestHeaders) && clientSessionIdMissing(requestHeaders)) {
            LOGGER.error("Missing IPV session and client session ID from headers");
            return new ValidationResult<>(false, ErrorResponse.MISSING_SESSION_ID);
        }

        var errorResult = validateRedirectUrl(queryStringParameters);
        return errorResult
                .map(errorResponse -> new ValidationResult<>(false, errorResponse))
                .orElseGet(ValidationResult::createValidResult);
    }

    private boolean queryStringParamsMissing(Map<String, List<String>> queryStringParameters) {
        return Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty();
    }

    private boolean sessionIdMissing(Map<String, String> requestHeaders) {
        return StringUtils.isBlank(
                RequestHelper.getHeaderByKey(requestHeaders, IPV_SESSION_ID_HEADER_KEY));
    }

    private boolean clientSessionIdMissing(Map<String, String> requestHeaders) {
        return StringUtils.isBlank(
                RequestHelper.getHeaderByKey(requestHeaders, CLIENT_SESSION_ID_HEADER_KEY));
    }

    private Optional<ErrorResponse> validateRedirectUrl(
            Map<String, List<String>> queryStringParameters) {
        try {
            String redirectUrl =
                    getOnlyValueOrThrow(
                            queryStringParameters.getOrDefault(REDIRECT_URI_PARAM, List.of()));
            String clientId =
                    getOnlyValueOrThrow(
                            queryStringParameters.getOrDefault(CLIENT_ID_PARAM, List.of()));
            List<String> clientRedirectUrls = configService.getClientRedirectUrls(clientId);

            if (!clientRedirectUrls.contains(redirectUrl)) {
                LOGGER.error(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Invalid redirect URL for client id.")
                                .with(LOG_CLIENT_ID.getFieldName(), clientId)
                                .with(LOG_REDIRECT_URI.getFieldName(), redirectUrl));
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
                    String.format("Parameter must have exactly one value: %s", container));
        }
        return container.get(0);
    }
}
