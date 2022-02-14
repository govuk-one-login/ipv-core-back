package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthRequestValidatorTest {

    @Mock private ConfigurationService mockConfigurationService;

    private static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String CLIENT_ID_PARAM = "client_id";
    private static final String RESPONSE_TYPE_PARAM = "response_type";
    private static final String SCOPE_PARAM = "scope";
    private static final String IPV_SESSION_ID_HEADER = "ipv-session-id";

    private static final Map<String, String> REQUEST_HEADERS =
            Map.of(IPV_SESSION_ID_HEADER, "12345");
    private static final Map<String, List<String>> VALID_QUERY_STRING_PARAMS =
            Map.of(
                    REDIRECT_URI_PARAM, List.of("http://example.com"),
                    CLIENT_ID_PARAM, List.of("12345"),
                    RESPONSE_TYPE_PARAM, List.of("code"),
                    SCOPE_PARAM, List.of("openid"));

    private AuthRequestValidator validator;

    @BeforeEach
    void setUp() {
        validator = new AuthRequestValidator(mockConfigurationService);
    }

    @Test
    void validateRequestReturnsValidResultForValidRequest() {
        when(mockConfigurationService.getClientRedirectUrls("12345"))
                .thenReturn(List.of("http://example.com"));

        var validationResult =
                validator.validateRequest(VALID_QUERY_STRING_PARAMS, REQUEST_HEADERS);

        assertTrue(validationResult.isValid());
    }

    @Test
    void validateRequestReturnsErrorResponseForNullParams() {
        var validationResult = validator.validateRequest(null, REQUEST_HEADERS);

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(),
                validationResult.getError().getMessage());
    }

    @Test
    void validateRequestReturnsErrorResponseForEmptyParameters() {
        var validationResult = validator.validateRequest(Collections.emptyMap(), REQUEST_HEADERS);

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(),
                validationResult.getError().getMessage());
    }

    @Test
    void validateRequestReturnsErrorResponseForMissingSessionId() {
        var validationResult =
                validator.validateRequest(VALID_QUERY_STRING_PARAMS, Collections.emptyMap());

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                validationResult.getError().getMessage());
    }

    @Test
    void validateRequestReturnsErrorResponseForBlankSessionId() {
        var validationResult =
                validator.validateRequest(
                        VALID_QUERY_STRING_PARAMS, Map.of(IPV_SESSION_ID_HEADER, ""));

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                validationResult.getError().getMessage());
    }

    @Test
    void validateRequestReturnsErrorIfMissingParamsForValidatingRedirectUrl() {
        var paramsToTest = List.of(REDIRECT_URI_PARAM, CLIENT_ID_PARAM);
        for (String paramToTest : paramsToTest) {
            var invalidQueryStringParams = new HashMap<>(VALID_QUERY_STRING_PARAMS);
            invalidQueryStringParams.remove(paramToTest);

            ValidationResult<ErrorResponse> validationResult =
                    validator.validateRequest(invalidQueryStringParams, REQUEST_HEADERS);

            assertFalse(validationResult.isValid());
            assertEquals(
                    ErrorResponse.INVALID_REQUEST_PARAM.getCode(),
                    validationResult.getError().getCode());
            assertEquals(
                    ErrorResponse.INVALID_REQUEST_PARAM.getMessage(),
                    validationResult.getError().getMessage());
        }
    }

    @Test
    void validateRequestReturnsErrorIfRedirectUrlNotRegistered() {
        List<String> registeredRedirectUrls =
                List.of(
                        "https://wrong.example.com",
                        "https://nope.example.com",
                        "https://whoops.example.com");
        when(mockConfigurationService.getClientRedirectUrls("12345"))
                .thenReturn(registeredRedirectUrls);

        var validationResult =
                validator.validateRequest(VALID_QUERY_STRING_PARAMS, REQUEST_HEADERS);

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.INVALID_REDIRECT_URL.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.INVALID_REDIRECT_URL.getMessage(),
                validationResult.getError().getMessage());
    }

    @Test
    void shouldSuccessFullyReadClaimSetProvided() {
        String tokenRequestBody =
                "code=12345&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        ValidationResult<ErrorObject> extractJwt = validator.extractJwt(tokenRequestBody);
        assertEquals(extractJwt.isValid(), true);
    }

    @Test
    void shouldReadClaimSetProvidedAndError() {
        String tokenRequestBody =
                "code=12345&client_assertion=&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        ValidationResult<ErrorObject> extractJwt = validator.extractJwt(tokenRequestBody);
        assertEquals(!extractJwt.isValid(), true);
        assertEquals(extractJwt.getError().getCode(), OAuth2Error.INVALID_CLIENT_CODE);
    }

    @Test
    void shouldReadClaimSetProvidedAndErrorWithMissingClaimSet() {
        String tokenRequestBody =
                "code=12345&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        ValidationResult<ErrorObject> extractJwt = validator.extractJwt(tokenRequestBody);
        assertEquals(!extractJwt.isValid(), true);
        assertEquals(extractJwt.getError().getCode(), OAuth2Error.INVALID_CLIENT_CODE);
    }
}
