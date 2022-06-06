package uk.gov.di.ipv.core.useridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AccessTokenService;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserIdentityHandlerTest {

    private static final String TEST_IPV_SESSION_ID = UUID.randomUUID().toString();
    public static final String VTM = "http://www.example.com/vtm";

    @Mock private Context mockContext;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private AccessTokenService mockAccessTokenService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private AuditService mockAuditService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private UserIdentityHandler userInfoHandler;
    private UserIdentity userIdentity;
    private IpvSessionItem ipvSessionItem;
    private Map<String, String> responseBody;

    @BeforeEach
    void setUp() {
        responseBody = new HashMap<>();

        List<Name> names =
                Collections.singletonList(
                        new Name(Collections.singletonList(new NameParts("GivenName", "Daniel"))));
        List<BirthDate> birthDates = Collections.singletonList(new BirthDate("1990-02-10"));

        userIdentity =
                new UserIdentity(
                        List.of("12345", "Test credential", "bar"),
                        new IdentityClaim(names, birthDates),
                        "test-sub",
                        VectorOfTrust.P2.toString(),
                        VTM);

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("12345");
        ipvSessionItem.setUserState("test-state");
        ipvSessionItem.setClientSessionDetails(
                new ClientSessionDetailsDto(
                        "code",
                        "test-client",
                        "http://example.com",
                        "test-state",
                        "test-user-id",
                        false));

        userInfoHandler =
                new UserIdentityHandler(
                        mockUserIdentityService,
                        mockAccessTokenService,
                        mockIpvSessionService,
                        mockConfigurationService,
                        mockAuditService);
    }

    @Test
    void shouldReturn200OnSuccessfulUserIdentityRequest()
            throws HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString()))
                .thenReturn(TEST_IPV_SESSION_ID);
        when(mockUserIdentityService.generateUserIdentity(any(), any())).thenReturn(userIdentity);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);

        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnCredentialsOnSuccessfulUserInfoRequest()
            throws JsonProcessingException, SqsException, HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString()))
                .thenReturn(TEST_IPV_SESSION_ID);
        when(mockUserIdentityService.generateUserIdentity(any(), any())).thenReturn(userIdentity);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        UserIdentity responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(userIdentity.getVcs().get(0), responseBody.getVcs().get(0));
        assertEquals(userIdentity.getVcs().get(1), responseBody.getVcs().get(1));
        assertEquals(userIdentity.getVcs().get(2), responseBody.getVcs().get(2));

        verify(mockAuditService).sendAuditEvent(AuditEventTypes.IPV_IDENTITY_ISSUED);
    }

    @Test
    void shouldReturnErrorResponseWhenUserIdentityGenerationFails()
            throws JsonProcessingException, SqsException, HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString()))
                .thenReturn(TEST_IPV_SESSION_ID);
        when(mockUserIdentityService.generateUserIdentity(any(), any()))
                .thenThrow(
                        new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM));
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);

        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                String.valueOf(ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getCode()),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsNull() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", null);
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissingBearerPrefix() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", "11111111");
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(
                BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.INVALID_REQUEST.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenInvalidAccessTokenProvided() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString())).thenReturn(null);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - The supplied access token was not found in the database")
                        .getDescription(),
                responseBody.get("error_description"));
    }
}
