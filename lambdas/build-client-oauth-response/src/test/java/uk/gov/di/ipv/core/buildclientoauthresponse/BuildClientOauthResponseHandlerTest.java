package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.core.buildclientoauthresponse.validation.AuthRequestValidator;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.IP_ADDRESS;

@ExtendWith(MockitoExtension.class)
class BuildClientOauthResponseHandlerTest {
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of(IPV_SESSION_ID, "12345", IP_ADDRESS, "192.168.1.100");
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private IpvSessionService mockSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;
    @Mock private AuthRequestValidator mockAuthRequestValidator;
    @Mock private AuditService mockAuditService;

    private BuildClientOauthResponseHandler handler;
    private String authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode().getValue();
        handler =
                new BuildClientOauthResponseHandler(
                        mockSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        mockAuthRequestValidator,
                        mockAuditService);
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequest()
            throws JsonProcessingException, SqsException, URISyntaxException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItem = generateIpvSessionItem();
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        Map<String, Object> response = handler.handleRequest(TEST_EVENT_HEADERS, context);

        ClientResponse responseBody =
                objectMapper.convertValue(response, new TypeReference<>() {});

        verify(mockSessionService)
                .setAuthorizationCode(eq(ipvSessionItem), anyString(), eq("https://example.com"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_END, auditEventCaptor.getValue().getEventName());

        URI expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode)
                        .addParameter("state", "test-state")
                        .build();

        URI actualRedirectUrl = new URI(responseBody.getClient().getRedirectUrl());
        List<NameValuePair> params =
                URLEncodedUtils.parse(actualRedirectUrl, StandardCharsets.UTF_8);
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertNotNull(params.get(0).getValue());
        assertEquals("test-state", params.get(1).getValue());
    }

    @Test
    void shouldReturn200WhenStateNotInSession() throws Exception {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setState("");
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> response = handler.handleRequest(TEST_EVENT_HEADERS, context);

        ClientResponse responseBody =
                objectMapper.convertValue(response, new TypeReference<>() {});

        assertNotNull(responseBody);
    }

    @Test
    void shouldReturn400IfRequestFailsValidation() throws JsonProcessingException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS));
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        Map<String, Object> responseBody = handler.handleRequest(TEST_EVENT_HEADERS, context);

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
            when(mockSessionService.getIpvSession(anyString()))
                    .thenReturn(generateIpvSessionItem());
            ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
            if (param.equals(OAuth2RequestParams.CLIENT_ID)) {
                clientOAuthSessionItem.setClientId(null);
            } else if (param.equals(OAuth2RequestParams.RESPONSE_TYPE)) {
                clientOAuthSessionItem.setResponseType(null);
            }
            when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);

            Map<String, Object> responseBody = handler.handleRequest(TEST_EVENT_HEADERS, context);
            // assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
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
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> response = handler.handleRequest(TEST_EVENT_HEADERS, context);

        ClientResponse responseBody =
                objectMapper.convertValue(response, new TypeReference<>() {});

        URIBuilder uriBuilder = new URIBuilder(responseBody.getClient().getRedirectUrl());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, uriBuilder.getQueryParams().get(0).getValue());
        assertEquals("Test error description", uriBuilder.getQueryParams().get(1).getValue());
        assertEquals(
                clientOAuthSessionItem.getState(), uriBuilder.getQueryParams().get(2).getValue());
    }

    @Test
    void shouldReturn200WithErrorParamsButWithoutStateIfNotRequired() throws Exception {
        IpvSessionItem ipvSessionItemWithError = generateIpvSessionItem();
        ipvSessionItemWithError.setErrorCode(OAuth2Error.SERVER_ERROR_CODE);
        ipvSessionItemWithError.setErrorDescription("Test error description");

        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItemWithError);
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setState(null);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        Map<String, Object> response = handler.handleRequest(TEST_EVENT_HEADERS, context);

        ClientResponse responseBody =
                objectMapper.convertValue(response, new TypeReference<>() {});

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
        return item;
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        clientOAuthSessionItem.setResponseType("code");
        clientOAuthSessionItem.setClientId("test-client-id");
        clientOAuthSessionItem.setRedirectUri("https://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        return clientOAuthSessionItem;
    }
}
