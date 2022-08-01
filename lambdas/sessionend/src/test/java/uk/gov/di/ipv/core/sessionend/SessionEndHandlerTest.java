package uk.gov.di.ipv.core.sessionend;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.library.validation.ValidationResult;
import uk.gov.di.ipv.core.sessionend.domain.ClientResponse;

import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
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
    void shouldReturn200OnSuccessfulOauthRequest()
            throws JsonProcessingException, SqsException, URISyntaxException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItem = generateIpvSessionItem();
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(VALID_QUERY_PARAMS);
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        verify(mockSessionService)
                .setAuthorizationCode(
                        ipvSessionItem, authorizationCode.getValue(), "https://example.com");

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_END, auditEventCaptor.getValue().getEventName());

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode.toString())
                        .addParameter("state", "test-state")
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
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

        verify(mockSessionService, never()).setAuthorizationCode(any(), anyString(), anyString());
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
            verify(mockSessionService, never())
                    .setAuthorizationCode(any(), anyString(), anyString());
        }
    }

    @Test
    void shouldReturn200WithErrorParams() throws Exception {
        IpvSessionItem ipvSessionItemWithError = generateIpvSessionItem();
        ipvSessionItemWithError.setErrorCode(OAuth2Error.SERVER_ERROR_CODE);
        ipvSessionItemWithError.setErrorDescription("Test error description");
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItemWithError);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(VALID_QUERY_PARAMS);
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        URIBuilder uriBuilder = new URIBuilder(responseBody.getClient().getRedirectUrl());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, uriBuilder.getQueryParams().get(0).getValue());
        assertEquals("Test error description", uriBuilder.getQueryParams().get(1).getValue());
        assertEquals(
                ipvSessionItemWithError.getClientSessionDetails().getState(),
                uriBuilder.getQueryParams().get(2).getValue());
    }

    @Test
    void shouldReturn200WithErrorParamsButWithoutStateIfNotRequired() throws Exception {
        IpvSessionItem ipvSessionItemWithError = generateIpvSessionItem();
        ipvSessionItemWithError.setErrorCode(OAuth2Error.SERVER_ERROR_CODE);
        ipvSessionItemWithError.setErrorDescription("Test error description");

        ClientSessionDetailsDto clientSessionDetailsDto = generateValidClientSessionDetailsDto();
        clientSessionDetailsDto.setState(null);
        ipvSessionItemWithError.setClientSessionDetails(clientSessionDetailsDto);

        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItemWithError);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(VALID_QUERY_PARAMS);
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        URIBuilder uriBuilder = new URIBuilder(responseBody.getClient().getRedirectUrl());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, uriBuilder.getQueryParams().get(0).getValue());
        assertEquals("Test error description", uriBuilder.getQueryParams().get(1).getValue());
        assertEquals(2, uriBuilder.getQueryParams().size());
    }

    private IpvSessionItem generateIpvSessionItem() {
        IpvSessionItem item = new IpvSessionItem();
        item.setIpvSessionId(SecureTokenHelper.generate());
        item.setUserState("test-state");
        item.setCreationDateTime(new Date().toString());

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "code",
                        "test-client-id",
                        "https://example.com",
                        "test-state",
                        "test-user-id",
                        false);
        item.setClientSessionDetails(clientSessionDetailsDto);

        return item;
    }

    private ClientSessionDetailsDto generateValidClientSessionDetailsDto() {
        return new ClientSessionDetailsDto(
                "code",
                "test-client-id",
                "https://example.com",
                "test-state",
                "test-user-id",
                false);
    }
}
