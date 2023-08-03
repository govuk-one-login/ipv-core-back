package uk.gov.di.ipv.core.builduseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.BUNDLE_CIMIT_VC;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.USE_CONTRA_INDICATOR_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.ADDRESS_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DRIVING_PERMIT_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.PASSPORT_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC;

@ExtendWith(MockitoExtension.class)
class BuildUserIdentityHandlerTest {

    private static final String TEST_IPV_SESSION_ID = SecureTokenHelper.generate();
    private static final String TEST_ACCESS_TOKEN = "test-access-token";
    private static final String VTM = "http://www.example.com/vtm";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();

    @Mock private Context mockContext;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private CiMitService mockCiMitService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private BuildUserIdentityHandler userInfoHandler;
    private UserIdentity userIdentity;
    private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;
    private Map<String, String> responseBody;

    @BeforeEach
    void setUp() throws Exception {
        responseBody = new HashMap<>();

        List<Name> names =
                Collections.singletonList(
                        new Name(Collections.singletonList(new NameParts("GivenName", "Daniel"))));
        List<BirthDate> birthDates = Collections.singletonList(new BirthDate("1990-02-10"));

        userIdentity =
                new UserIdentity(
                        List.of("12345", "Test credential", "bar"),
                        new IdentityClaim(names, birthDates),
                        objectMapper.readTree(ADDRESS_JSON_1),
                        objectMapper.readTree(PASSPORT_JSON_1),
                        objectMapper.readTree(DRIVING_PERMIT_JSON_1),
                        "test-sub",
                        VectorOfTrust.P2.toString(),
                        VTM);

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.setUserState("test-state");
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setAccessToken(TEST_ACCESS_TOKEN);
        ipvSessionItem.setAccessTokenMetadata(new AccessTokenMetadata());
        ipvSessionItem.setVot("P2");

        userInfoHandler =
                new BuildUserIdentityHandler(
                        mockUserIdentityService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockAuditService,
                        mockClientOAuthSessionDetailsService,
                        mockCiMitService);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId("test-user-id")
                        .clientId("test-client")
                        .govukSigninJourneyId("test-journey-id")
                        .build();
    }

    @Test
    void shouldReturn200OnSuccessfulUserIdentityRequest()
            throws HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);

        assertEquals(200, response.getStatusCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnCredentialsOnSuccessfulUserInfoRequest()
            throws JsonProcessingException, SqsException, HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        UserIdentity responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(userIdentity.getVcs().get(0), responseBody.getVcs().get(0));
        assertEquals(userIdentity.getVcs().get(1), responseBody.getVcs().get(1));
        assertEquals(userIdentity.getVcs().get(2), responseBody.getVcs().get(2));
        assertEquals(userIdentity.getIdentityClaim(), responseBody.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), responseBody.getAddressClaim());
        assertEquals(userIdentity.getDrivingPermitClaim(), responseBody.getDrivingPermitClaim());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_ISSUED, auditEventCaptor.getValue().getEventName());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnCredentialsWithCiMitVCOnSuccessfulUserInfoRequest()
            throws JsonProcessingException, SqsException, HttpResponseExceptionWithErrorBody,
                    CiRetrievalException, ParseException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockConfigService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(true);
        when(mockConfigService.enabled(BUNDLE_CIMIT_VC)).thenReturn(true);
        when(mockCiMitService.getContraIndicatorsVCJwt(any(), any(), any()))
                .thenReturn(SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC));

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        UserIdentity responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(userIdentity.getVcs().size(), 4);
        assertEquals(userIdentity.getVcs().get(0), responseBody.getVcs().get(0));
        assertEquals(userIdentity.getVcs().get(1), responseBody.getVcs().get(1));
        assertEquals(userIdentity.getVcs().get(2), responseBody.getVcs().get(2));
        assertEquals(SIGNED_CONTRA_INDICATOR_VC, responseBody.getVcs().get(3));
        assertEquals(userIdentity.getIdentityClaim(), responseBody.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), responseBody.getAddressClaim());
        assertEquals(userIdentity.getDrivingPermitClaim(), responseBody.getDrivingPermitClaim());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_ISSUED, auditEventCaptor.getValue().getEventName());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCiMitService, times(1)).getContraIndicatorsVCJwt(any(), any(), any());
    }

    @Test
    void
            shouldReturnCredentialsWithoutCiMitVCOnSuccessfulUserInfoRequestWhenBundleCimitVCFeatureFlagIsNotEnabled()
                    throws JsonProcessingException, SqsException,
                            HttpResponseExceptionWithErrorBody, CiRetrievalException,
                            ParseException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockConfigService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(true);
        when(mockConfigService.enabled(BUNDLE_CIMIT_VC)).thenReturn(false);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        UserIdentity responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(userIdentity.getVcs().size(), 3);
        assertEquals(userIdentity.getVcs().get(0), responseBody.getVcs().get(0));
        assertEquals(userIdentity.getVcs().get(1), responseBody.getVcs().get(1));
        assertEquals(userIdentity.getVcs().get(2), responseBody.getVcs().get(2));
        assertEquals(userIdentity.getIdentityClaim(), responseBody.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), responseBody.getAddressClaim());
        assertEquals(userIdentity.getDrivingPermitClaim(), responseBody.getDrivingPermitClaim());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_ISSUED, auditEventCaptor.getValue().getEventName());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCiMitService, times(0)).getContraIndicatorsVCJwt(any(), any(), any());
    }

    @Test
    void shouldReturnErrorResponseWhenUserIdentityGenerationFails()
            throws JsonProcessingException, HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any()))
                .thenThrow(
                        new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);

        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                String.valueOf(ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getCode()),
                responseBody.get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getMessage(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnErrorResponseOnCIRetrievalException()
            throws JsonProcessingException, HttpResponseExceptionWithErrorBody,
                    CiRetrievalException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockConfigService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(true);
        when(mockConfigService.enabled(BUNDLE_CIMIT_VC)).thenReturn(true);
        when(mockCiMitService.getContraIndicatorsVCJwt(any(), any(), any()))
                .thenThrow(
                        new CiRetrievalException("Error when fetching CIs from storage system."));

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals("server_error", responseBody.get("error"));
        assertEquals("Unexpected server error", responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCiMitService, times(1)).getContraIndicatorsVCJwt(any(), any(), any());
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsNull() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = new HashMap<>(Collections.emptyMap());
        headers.put("Authorization", null);
        headers.put("ip-address", TEST_IP_ADDRESS);
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissingBearerPrefix() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers =
                Map.of("Authorization", "11111111", "ip-address", TEST_IP_ADDRESS);
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(
                BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.INVALID_REQUEST.getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Map.of("ip-address", TEST_IP_ADDRESS);
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnErrorResponseWhenInvalidAccessTokenProvided() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(null));

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
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnErrorResponseWhenAccessTokenHasBeenRevoked() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        AccessTokenMetadata revokedAccessTokenMetadata = new AccessTokenMetadata();
        revokedAccessTokenMetadata.setRevokedAtDateTime(Instant.now().toString());
        ipvSessionItem.setAccessTokenMetadata(revokedAccessTokenMetadata);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has been revoked")
                        .getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn403ErrorResponseWhenAccessTokenHasExpired() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);

        AccessTokenMetadata expiredAccessTokenMetadata = new AccessTokenMetadata();
        expiredAccessTokenMetadata.setExpiryDateTime(Instant.now().minusSeconds(5).toString());
        ipvSessionItem.setAccessTokenMetadata(expiredAccessTokenMetadata);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(Optional.ofNullable(ipvSessionItem));

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }
}
