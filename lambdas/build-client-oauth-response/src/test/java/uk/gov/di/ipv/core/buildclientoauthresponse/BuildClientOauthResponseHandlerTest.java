package uk.gov.di.ipv.core.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
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
import uk.gov.di.ipv.core.library.domain.BaseResponse;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BuildClientOauthResponseHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    public static final String TEST_FEATURE_SET = "fs-001";
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
            throws IOException, SqsException, URISyntaxException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItem = generateIpvSessionItem();
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();
        var clientResponse = makeRequest(event, context, ClientResponse.class);

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

        URI actualRedirectUrl = new URI(clientResponse.getClient().getRedirectUrl());
        List<NameValuePair> params =
                URLEncodedUtils.parse(actualRedirectUrl, StandardCharsets.UTF_8);
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertNotNull(params.get(0).getValue());
        assertEquals("test-state", params.get(1).getValue());
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequest_withNullIpvSessionAndClientSessionIdInRequest()
            throws IOException, URISyntaxException {
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .featureSet(TEST_FEATURE_SET)
                        .build();
        var clientResponse = makeRequest(event, context, ClientResponse.class);

        URI actualRedirectUrl = new URI(clientResponse.getClient().getRedirectUrl());
        List<NameValuePair> params =
                URLEncodedUtils.parse(actualRedirectUrl, StandardCharsets.UTF_8);
        assertEquals("example.com", actualRedirectUrl.getHost());
        assertEquals("access_denied", params.get(0).getValue());
        assertEquals("Missing Context", params.get(1).getValue());
        assertEquals("test-state", params.get(2).getValue());
        verify(mockConfigService).setFeatureSet(TEST_FEATURE_SET);
    }

    @Test
    void shouldReturn400_withBothIpvSessionAndClientSessionIdNullInRequest() throws IOException {
        JourneyRequest event = JourneyRequest.builder().ipAddress(TEST_IP_ADDRESS).build();
        var errorResponse = makeRequest(event, context, JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, errorResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_SESSION_ID.getCode(), errorResponse.getCode());
        assertEquals(ErrorResponse.MISSING_SESSION_ID.getMessage(), errorResponse.getMessage());
    }

    @Test
    void shouldReturn200WhenStateNotInSession() throws IOException, URISyntaxException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setState("");
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();
        var clientResponse = makeRequest(event, context, ClientResponse.class);

        URI expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode)
                        .build();
        URI actualRedirectUrl = new URI(clientResponse.getClient().getRedirectUrl());
        List<NameValuePair> params =
                URLEncodedUtils.parse(actualRedirectUrl, StandardCharsets.UTF_8);
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertEquals(1, params.size());
        assertNotNull(params.get(0).getValue());
    }

    @Test
    void shouldReturn400IfRequestFailsValidation() throws IOException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS));
        when(mockSessionService.getIpvSession(anyString())).thenReturn(generateIpvSessionItem());
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();
        var errorResponse = makeRequest(event, context, JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, errorResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), errorResponse.getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), errorResponse.getMessage());

        verify(mockSessionService, never()).setAuthorizationCode(any(), anyString(), anyString());
    }

    @Test
    void shouldReturn400IfCanNotParseAuthRequestFromQueryStringParams() throws IOException {
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

            JourneyRequest event =
                    JourneyRequest.builder()
                            .ipvSessionId(TEST_SESSION_ID)
                            .ipAddress(TEST_IP_ADDRESS)
                            .build();
            var errorResponse = makeRequest(event, context, JourneyErrorResponse.class);

            assertEquals(HttpStatus.SC_BAD_REQUEST, errorResponse.getStatusCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                    errorResponse.getCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                    errorResponse.getMessage());
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

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();
        var clientResponse = makeRequest(event, context, ClientResponse.class);

        URIBuilder uriBuilder = new URIBuilder(clientResponse.getClient().getRedirectUrl());
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

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .build();
        var clientResponse = makeRequest(event, context, ClientResponse.class);

        URIBuilder uriBuilder = new URIBuilder(clientResponse.getClient().getRedirectUrl());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, uriBuilder.getQueryParams().get(0).getValue());
        assertEquals("Test error description", uriBuilder.getQueryParams().get(1).getValue());
        assertEquals(2, uriBuilder.getQueryParams().size());
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequestForJsonRequest()
            throws SqsException, URISyntaxException {
        when(mockAuthRequestValidator.validateRequest(anyMap(), anyMap()))
                .thenReturn(ValidationResult.createValidResult());
        IpvSessionItem ipvSessionItem = generateIpvSessionItem();
        when(mockSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        JourneyRequest event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .build();
        var response = handler.handleRequest(event, context);

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

        ClientResponse responseBody = objectMapper.convertValue(response, ClientResponse.class);
        URI actualRedirectUrl = new URI(responseBody.getClient().getRedirectUrl());
        List<NameValuePair> params =
                URLEncodedUtils.parse(actualRedirectUrl, StandardCharsets.UTF_8);
        assertEquals(expectedRedirectUrl.getHost(), actualRedirectUrl.getHost());
        assertNotNull(params.get(0).getValue());
        assertEquals("test-state", params.get(1).getValue());
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

    private <T extends BaseResponse> T makeRequest(
            JourneyRequest request, Context context, Class<T> classType) throws IOException {
        try (var inputStream =
                        new ByteArrayInputStream(
                                objectMapper.writeValueAsString(request).getBytes());
                var outputStream = new ByteArrayOutputStream()) {
            handler.handleRequest(inputStream, outputStream, context);
            return objectMapper.readValue(outputStream.toString(), classType);
        }
    }
}
