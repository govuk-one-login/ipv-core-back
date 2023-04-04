package uk.gov.di.ipv.core.buildcrioauthrequest;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.credentialissuer.CredentialIssuerConfigService;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_3;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_4;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.vcClaim;

@ExtendWith(MockitoExtension.class)
class BuildCriOauthRequestHandlerTest {

    private static final String CRI_ID = "PassportIssuer";
    private static final String DCMAW_CRI_ID = "dcmaw";
    private static final String ADDRESS_CRI_ID = "address";
    private static final String KBV_CRI_ID = "kbv";
    private static final String CRI_NAME = "any";
    private static final String CRI_TOKEN_URL = "http://www.example.com";
    private static final String CRI_CREDENTIAL_URL = "http://www.example.com/credential";
    private static final String CRI_AUTHORIZE_URL = "http://www.example.com/authorize";
    private static final String IPV_ISSUER = "http://www.example.com/issuer";
    private static final String ADDRESS_ISSUER = "http://www.example.com/address/issuer";
    private static final String CRI_AUDIENCE = "http://www.example.com/audience";
    private static final String IPV_CLIENT_ID = "ipv-core";
    private static final String SESSION_ID = "the-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";

    private static final String TEST_SHARED_CLAIMS = "shared_claims";

    public static final String CRI_OAUTH_SESSION_ID = "cri-oauth-session-id";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private CredentialIssuerConfigService configService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;

    private CredentialIssuerConfig credentialIssuerConfig;
    private CredentialIssuerConfig addressCredentialIssuerConfig;
    private CredentialIssuerConfig dcmawCredentialIssuerConfig;
    private CredentialIssuerConfig kbvCredentialIssuerConfig;
    private BuildCriOauthRequestHandler underTest;
    private ClientSessionDetailsDto clientSessionDetailsDto;
    private CriOAuthSessionItem criOAuthSessionItem;

    @BeforeEach
    void setUp()
            throws URISyntaxException, InvalidKeySpecException, NoSuchAlgorithmException,
                    JOSEException {
        ECDSASigner signer = new ECDSASigner(getSigningPrivateKey());

        underTest =
                new BuildCriOauthRequestHandler(
                        configService,
                        userIdentityService,
                        signer,
                        mockAuditService,
                        mockIpvSessionService,
                        mockCriOAuthSessionService);
        credentialIssuerConfig =
                new CredentialIssuerConfig(
                        CRI_ID,
                        CRI_NAME,
                        new URI(CRI_TOKEN_URL),
                        new URI(CRI_CREDENTIAL_URL),
                        new URI(CRI_AUTHORIZE_URL),
                        IPV_CLIENT_ID,
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "http://www.example.com/audience",
                        URI.create("http://www.example.com/callback/criId"));

        addressCredentialIssuerConfig =
                new CredentialIssuerConfig(
                        ADDRESS_CRI_ID,
                        CRI_NAME,
                        new URI(CRI_TOKEN_URL),
                        new URI(CRI_CREDENTIAL_URL),
                        new URI(CRI_AUTHORIZE_URL),
                        IPV_CLIENT_ID,
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        ADDRESS_ISSUER,
                        URI.create("http://www.example.com/callback/criId"));

        dcmawCredentialIssuerConfig =
                new CredentialIssuerConfig(
                        DCMAW_CRI_ID,
                        CRI_NAME,
                        new URI(CRI_TOKEN_URL),
                        new URI(CRI_CREDENTIAL_URL),
                        new URI(CRI_AUTHORIZE_URL),
                        IPV_CLIENT_ID,
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "http://www.example.com/audience",
                        URI.create("http://www.example.com/callback/criId"));

        kbvCredentialIssuerConfig =
                new CredentialIssuerConfig(
                        KBV_CRI_ID,
                        CRI_NAME,
                        new URI(CRI_TOKEN_URL),
                        new URI(CRI_CREDENTIAL_URL),
                        new URI(CRI_AUTHORIZE_URL),
                        IPV_CLIENT_ID,
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "http://www.example.com/audience",
                        URI.create("http://www.example.com/callback/criId"));

        clientSessionDetailsDto = new ClientSessionDetailsDto();
        clientSessionDetailsDto.setUserId(TEST_USER_ID);
        clientSessionDetailsDto.setGovukSigninJourneyId("test-journey-id");

        criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(CRI_OAUTH_SESSION_ID)
                        .criId(CRI_ID)
                        .accessToken("testAccessToken")
                        .authorizationCode("testAuthorizationCode")
                        .build();
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", "Missing CriId"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithoutResponseTypeParam()
            throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CRI_ID))
                .thenReturn(credentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, true)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_1), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_2), IPV_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        assertEquals(CRI_ID, responseBody.get("id"));

        Optional<NameValuePair> client_id =
                queryParams.stream()
                        .filter(param -> param.getName().equals("client_id"))
                        .findFirst();
        assertTrue(client_id.isPresent());
        assertEquals(IPV_CLIENT_ID, client_id.get().getValue());

        Optional<NameValuePair> response_type =
                queryParams.stream()
                        .filter(param -> param.getName().equals("response_type"))
                        .findFirst();
        assertFalse(response_type.isPresent());

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();
        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        assertEquals(CRI_AUTHORIZE_URL, redirectUri.removeQuery().build().toString());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEventCaptor.getValue().getEventName());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1)).persistCriOAuthSession(any(), any());
    }

    @Test
    void shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithResponseTypeParam()
            throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI_ID))
                .thenReturn(dcmawCredentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, true)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_1), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_2), IPV_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", DCMAW_CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        assertEquals(DCMAW_CRI_ID, responseBody.get("id"));

        Optional<NameValuePair> client_id =
                queryParams.stream()
                        .filter(param -> param.getName().equals("client_id"))
                        .findFirst();
        assertTrue(client_id.isPresent());
        assertEquals(IPV_CLIENT_ID, client_id.get().getValue());

        Optional<NameValuePair> response_type =
                queryParams.stream()
                        .filter(param -> param.getName().equals("response_type"))
                        .findFirst();
        assertTrue(response_type.isPresent());
        assertEquals("code", response_type.get().getValue());

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();
        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        assertEquals(CRI_AUTHORIZE_URL, redirectUri.removeQuery().build().toString());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEventCaptor.getValue().getEventName());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1)).persistCriOAuthSession(any(), any());
    }

    @Test
    void shouldReturn400IfSessionIdIsNotInTheHeader() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("not-ipv-session-header", "dummy-value"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(400, response.getStatusCode());
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals("Missing ipv session id header", responseBody.get("error_description"));
    }

    private void assertSharedClaimsJWTIsValid(String request)
            throws ParseException, JsonProcessingException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(request);
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        assertEquals(IPV_CLIENT_ID, signedJWT.getJWTClaimsSet().getClaim("client_id"));
        assertEquals(IPV_ISSUER, signedJWT.getJWTClaimsSet().getIssuer());
        assertEquals(TEST_USER_ID, signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(CRI_AUDIENCE, signedJWT.getJWTClaimsSet().getAudience().get(0));

        assertEquals(3, claimsSet.get(TEST_SHARED_CLAIMS).size());
        JsonNode vcAttributes = claimsSet.get(TEST_SHARED_CLAIMS);

        JsonNode address = vcAttributes.get("address");

        List<Address> addressList = new ArrayList<>();
        for (JsonNode jo : address) {
            addressList.add(objectMapper.convertValue(jo, Address.class));
        }

        Address streetAddress =
                addressList.stream()
                        .filter(x -> "NotDowningStreet".equals(x.getStreetName()))
                        .findAny()
                        .orElse(null);
        Address postCode =
                addressList.stream()
                        .filter(x -> "SW1A2AA".equals(x.getPostalCode()))
                        .findAny()
                        .orElse(null);

        assertFalse(streetAddress.getStreetName().isEmpty());
        assertFalse(postCode.getPostalCode().isEmpty());

        assertEquals(2, (vcAttributes.get("name")).size());
        assertEquals(3, (vcAttributes.get("address")).size());
        assertEquals(2, (vcAttributes.get("birthDate")).size());

        ECDSAVerifier verifier = new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK));
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    void shouldDeduplicateSharedClaims() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CRI_ID))
                .thenReturn(credentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, true)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_1), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_1), IPV_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode sharedClaims = claimsSet.get(TEST_SHARED_CLAIMS);
        assertEquals(1, sharedClaims.get("name").size());
        assertEquals(2, sharedClaims.get("birthDate").size());
        assertEquals(2, sharedClaims.get("address").size());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1)).persistCriOAuthSession(any(), any());
    }

    @Test
    void shouldNotDeduplicateSharedClaimsIfFullNameDifferent() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CRI_ID))
                .thenReturn(credentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, true)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_2), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_3), IPV_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode sharedClaims = claimsSet.get(TEST_SHARED_CLAIMS);
        assertEquals(2, sharedClaims.get("name").size());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1)).persistCriOAuthSession(any(), any());
    }

    @Test
    void shouldDeduplicateNamesThatAppearInDifferentVCs() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CRI_ID))
                .thenReturn(credentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, true)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_3), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_4), IPV_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode names = claimsSet.get(TEST_SHARED_CLAIMS).get("name");
        JsonNode name1NameParts = names.get(0).get("nameParts");
        JsonNode name2NameParts = names.get(1).get("nameParts");

        assertEquals("GivenName", name1NameParts.get(0).get("type").asText());
        assertEquals("Alice", name1NameParts.get(0).get("value").asText());
        assertEquals("GivenName", name1NameParts.get(1).get("type").asText());
        assertEquals("Jane", name1NameParts.get(1).get("value").asText());
        assertEquals("GivenName", name1NameParts.get(2).get("type").asText());
        assertEquals("Laura", name1NameParts.get(2).get("value").asText());
        assertEquals("FamilyName", name1NameParts.get(3).get("type").asText());
        assertEquals("Doe", name1NameParts.get(3).get("value").asText());
        assertEquals("FamilyName", name1NameParts.get(4).get("type").asText());
        assertEquals("Musk", name1NameParts.get(4).get("value").asText());

        assertEquals("GivenName", name2NameParts.get(0).get("type").asText());
        assertEquals("Alice", name2NameParts.get(0).get("value").asText());
        assertEquals("GivenName", name2NameParts.get(1).get("type").asText());
        assertEquals("Jane", name2NameParts.get(1).get("value").asText());
        assertEquals("FamilyName", name2NameParts.get(2).get("type").asText());
        assertEquals("Doe", name2NameParts.get(2).get("value").asText());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1)).persistCriOAuthSession(any(), any());
    }

    @Test
    void shouldRemoveExtraAddressClaimsAndOnlyUseValuesFromTheAddressVC() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CRI_ID))
                .thenReturn(credentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, true)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_1), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_2), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_3), ADDRESS_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode sharedClaims = claimsSet.get(TEST_SHARED_CLAIMS);
        assertEquals(3, sharedClaims.get("name").size());
        assertEquals(2, sharedClaims.get("birthDate").size());
        assertEquals(1, sharedClaims.get("address").size());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1)).persistCriOAuthSession(any(), any());
    }

    @Test
    void shouldNotIncludeFailedVcsInTheSharedClaims() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CRI_ID))
                .thenReturn(credentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, false)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_1), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_2), ADDRESS_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode sharedClaims = claimsSet.get(TEST_SHARED_CLAIMS);
        assertEquals(1, sharedClaims.get("name").size());
        assertEquals(2, sharedClaims.get("birthDate").size());
        assertEquals(2, sharedClaims.get("address").size());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1)).persistCriOAuthSession(any(), any());
    }

    @Test
    void shouldOnlyAllowCRIConfiguredSharedClaimAttr() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CRI_ID))
                .thenReturn(kbvCredentialIssuerConfig);
        when(configService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(configService.getSsmParameter(AUDIENCE_FOR_CLIENTS)).thenReturn(IPV_ISSUER);
        when(configService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn(ADDRESS_CRI_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_ID))
                .thenReturn(addressCredentialIssuerConfig);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(IPV_ISSUER, true),
                                new VcStatusDto(ADDRESS_ISSUER, true)));
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_1), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_2), IPV_ISSUER),
                                generateVerifiableCredential(
                                        vcClaim(CREDENTIAL_ATTRIBUTES_3), ADDRESS_ISSUER)));
        when(mockCriOAuthSessionService.persistCriOAuthSession(any(), any()))
                .thenReturn(criOAuthSessionItem);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        URIBuilder redirectUri = new URIBuilder(responseBody.get("redirectUrl"));
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode sharedClaims = claimsSet.get(TEST_SHARED_CLAIMS);
        assertEquals(3, sharedClaims.get("name").size());
        assertEquals(2, sharedClaims.get("birthDate").size());
        assertEquals(1, sharedClaims.get("address").size());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
    }

    private Map<String, Map<String, String>> getResponseBodyAsMap(
            APIGatewayProxyResponseEvent response) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), Map.class);
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", "aSessionId", "ip-address", TEST_IP_ADDRESS));
        return input;
    }

    private void assert400Response(
            APIGatewayProxyResponseEvent response, ErrorResponse errorResponse)
            throws JsonProcessingException {
        Integer statusCode = response.getStatusCode();
        Map responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_BAD_REQUEST, statusCode);
        assertEquals(errorResponse.getCode(), responseBody.get("code"));
    }

    private ECPrivateKey getSigningPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }

    private PrivateKey getEncryptionPrivateKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(
                        new PKCS8EncodedKeySpec(
                                Base64.getDecoder().decode(RSA_ENCRYPTION_PRIVATE_KEY)));
    }
}
