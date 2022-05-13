package uk.gov.di.ipv.core.sessionend;

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
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.library.validation.ValidationResult;
import uk.gov.di.ipv.core.sessionend.domain.ClientResponse;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionEndHandlerTest {
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
    @Mock private IpvSessionService mockSessionService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private AuthRequestValidator mockAuthRequestValidator;
    @Mock private AuditService mockAuditService;

    private SessionEndHandler handler;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();
        handler =
                new SessionEndHandler(
                        mockAuthorizationCodeService,
                        mockSessionService,
                        mockConfigurationService,
                        mockAuthRequestValidator,
                        mockAuditService);
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequest() throws JsonProcessingException, SqsException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(VALID_QUERY_PARAMS);
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(
                        responseBody.getClient().getAuthCode(),
                        "12345",
                        responseBody.getClient().getRedirectUrl());

        verify(mockAuditService).sendAuditEvent(AuditEventTypes.IPV_JOURNEY_END);

        assertEquals(authorizationCode.toString(), responseBody.getClient().getAuthCode());
        assertEquals("https://example.com", responseBody.getClient().getRedirectUrl());
        assertEquals("test-state", responseBody.getClient().getState());
    }

    @Test
    void shouldReturn200WhenStateNotInSession() throws Exception {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItemWithoutState = generateIpvSessionItem();
        ipvSessionItemWithoutState.getClientSessionDetails().setState("");
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItemWithoutState);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(VALID_QUERY_PARAMS);
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertNull(responseBody.getClient().getState());
    }

    @Test
    void shouldReturn400IfRequestFailsValidation() throws JsonProcessingException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS));
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());

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
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());

        List<String> paramsToRemove =
                List.of(OAuth2RequestParams.CLIENT_ID, OAuth2RequestParams.RESPONSE_TYPE);
        for (String param : paramsToRemove) {
            IpvSessionItem item = generateIpvSessionItem();
            ClientSessionDetailsDto clientSessionDetailsDto =
                    generateValidClientSessionDetailsDto();
            if (param.equals(OAuth2RequestParams.CLIENT_ID)) {
                clientSessionDetailsDto.setClientId(null);
            } else if (param.equals(OAuth2RequestParams.RESPONSE_TYPE)) {
                clientSessionDetailsDto.setResponseType(null);
            }

            item.setClientSessionDetails(clientSessionDetailsDto);

            when(mockSessionService.getIpvSession(anyString())).thenReturn(item);

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
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

    private IpvSessionItem generateIpvSessionItem() {
        IpvSessionItem item = new IpvSessionItem();
        item.setIpvSessionId(UUID.randomUUID().toString());
        item.setUserState("test-state");
        item.setCreationDateTime(new Date().toString());

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "code",
                        "test-client-id",
                        "https://example.com",
                        "openid",
                        "test-state",
                        false,
                        null);
        item.setClientSessionDetails(clientSessionDetailsDto);

        return item;
    }

    private ClientSessionDetailsDto generateValidClientSessionDetailsDto() {
        return new ClientSessionDetailsDto(
                "code",
                "test-client-id",
                "https://example.com",
                "openid",
                "test-state",
                false,
                null);
    }
}
