package uk.gov.di.ipv.core.authorization;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationHandlerTest {
    private static final Map<String, String> TEST_EVENT_HEADERS = Map.of("ipv-session-id", "12345");
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Map<String, String> VALID_QUERY_PARAMS =
            Map.of(
                    OAuth2RequestParams.REDIRECT_URI, "http://example.com",
                    OAuth2RequestParams.CLIENT_ID, "12345",
                    OAuth2RequestParams.RESPONSE_TYPE, "code",
                    OAuth2RequestParams.SCOPE, "openid");

    @Mock private Context context;
    @Mock private AuthorizationCodeService mockAuthorizationCodeService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private AuthRequestValidator mockAuthRequestValidator;

    private AuthorizationHandler handler;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();
        handler =
                new AuthorizationHandler(
                        mockAuthorizationCodeService,
                        mockConfigurationService,
                        mockAuthRequestValidator);
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequest() throws JsonProcessingException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(VALID_QUERY_PARAMS);
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        Map<String, Map<String, String>> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        Map<String, String> authCode = responseBody.get("code");

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(authCode.get("value"), "12345", "http://example.com");
        assertEquals(authorizationCode.toString(), authCode.get("value"));
    }

    @Test
    void shouldReturn400IfRequestFailsValidation() throws JsonProcessingException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));

        verify(mockAuthorizationCodeService, never())
                .persistAuthorizationCode(anyString(), anyString(), anyString());
    }

    @Test
    void shouldReturn400IfCanNotParseAuthRequestFromQueryStringParams()
            throws JsonProcessingException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());

        List<String> paramsToRemove =
                List.of(
                        OAuth2RequestParams.REDIRECT_URI,
                        OAuth2RequestParams.CLIENT_ID,
                        OAuth2RequestParams.RESPONSE_TYPE,
                        OAuth2RequestParams.SCOPE);
        for (String param : paramsToRemove) {
            Map<String, String> unparseableParams = new HashMap<>(VALID_QUERY_PARAMS);
            unparseableParams.remove(param);

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(unparseableParams);
            event.setHeaders(TEST_EVENT_HEADERS);

            APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

            Map<String, Object> responseBody =
                    objectMapper.readValue(response.getBody(), new TypeReference<>() {});
            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                    responseBody.get("code"));
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                    responseBody.get("message"));
            verify(mockAuthorizationCodeService, never())
                    .persistAuthorizationCode(anyString(), anyString(), anyString());
        }
    }
}
