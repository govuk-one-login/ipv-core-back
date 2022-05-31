package uk.gov.di.ipv.core.credentialissuer;

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
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
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
import java.util.stream.Collectors;

import static java.util.Collections.emptyMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.credentialissuer.CredentialIssuerStartHandler.SHARED_CLAIMS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_3;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.vcClaim;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerStartHandlerTest {

    public static final String CRI_ID = "PassportIssuer";
    public static final String CRI_NAME = "any";
    public static final String CRI_TOKEN_URL = "http://www.example.com";
    public static final String CRI_CREDENTIAL_URL = "http://www.example.com/credential";
    public static final String CRI_AUTHORIZE_URL = "http://www.example.com/authorize";
    public static final String IPV_ISSUER = "http://www.example.com/issuer";
    public static final String CRI_AUDIENCE = "http://www.example.com/audience";
    public static final String IPV_CLIENT_ID = "ipv-core";
    public static final String SESSION_ID = "the-session-id";
    public static final String VTM = "http://www.example.com/vtm";
    public static final String TEST_USER_ID = "test-user-id";
    public static final String OAUTH_STATE = "test-state";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private ConfigurationService configurationService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;

    private ClientSessionDetailsDto clientSessionDetailsDto;

    private CredentialIssuerConfig credentialIssuerConfig;

    private CredentialIssuerStartHandler underTest;

    @BeforeEach
    void setUp()
            throws URISyntaxException, InvalidKeySpecException, NoSuchAlgorithmException,
                    JOSEException {
        ECDSASigner signer = new ECDSASigner(getSigningPrivateKey());

        underTest =
                new CredentialIssuerStartHandler(
                        configurationService,
                        userIdentityService,
                        signer,
                        mockAuditService,
                        mockIpvSessionService);
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
                        "http://www.example.com/audience");

        clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "code",
                        "test-client-id",
                        "https://example.com/redirect",
                        OAUTH_STATE,
                        TEST_USER_ID,
                        false,
                        new ErrorObject("server_error", "Test error"));
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent(emptyMap(), emptyMap());

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = createRequestEvent(emptyMap(), emptyMap());

        input.setPathParameters(Map.of("criId", "Missing CriId"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assert400Response(response, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive200ResponseCodeAndReturnCredentialIssuerResponse() throws Exception {
        when(configurationService.getCredentialIssuer(CRI_ID)).thenReturn(credentialIssuerConfig);
        when(configurationService.getIpvTokenTtl()).thenReturn("900");
        when(configurationService.getCoreFrontCallbackUrl()).thenReturn("callbackUrl");
        when(configurationService.getAudienceForClients()).thenReturn(IPV_ISSUER);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(vcClaim(CREDENTIAL_ATTRIBUTES_1)),
                                generateVerifiableCredential(vcClaim(CREDENTIAL_ATTRIBUTES_2))));

        APIGatewayProxyRequestEvent input = createRequestEvent(emptyMap(), emptyMap());

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");

        assertEquals(CRI_ID, responseBody.get("id"));
        assertEquals(IPV_CLIENT_ID, responseBody.get("ipvClientId"));
        assertEquals(CRI_AUTHORIZE_URL, responseBody.get("authorizeUrl"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());

        JWEObject jweObject = JWEObject.parse(responseBody.get("request"));
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        verifyNoInteractions(context);
        verify(mockAuditService).sendAuditEvent(AuditEventTypes.IPV_REDIRECT_TO_CRI);
    }

    @Test
    void shouldReturnErrorJourneyIfSessionIdIsNotInTheHeader() throws JsonProcessingException {
        when(configurationService.getCredentialIssuer(CRI_ID)).thenReturn(credentialIssuerConfig);
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("not-ipv-session-header", "dummy-value"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(200, response.getStatusCode());
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals("/journey/error", responseBody.get("journey"));
    }

    private void assertSharedClaimsJWTIsValid(String request)
            throws ParseException, JsonProcessingException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(request);
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        assertEquals(IPV_CLIENT_ID, signedJWT.getJWTClaimsSet().getClaim("client_id"));
        assertEquals(IPV_ISSUER, signedJWT.getJWTClaimsSet().getIssuer());
        assertEquals(TEST_USER_ID, signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(CRI_AUDIENCE, signedJWT.getJWTClaimsSet().getAudience().get(0));

        assertEquals(3, claimsSet.get(SHARED_CLAIMS).size());
        JsonNode vcAttributes = claimsSet.get(SHARED_CLAIMS);

        JsonNode address = vcAttributes.get("address");

        List<Address> addressList = new ArrayList<>();
        for (JsonNode jo : address) {
            addressList.add(objectMapper.convertValue(jo, Address.class));
        }

        Address streetAddress =
                addressList.stream()
                        .filter(x -> "35 Idsworth Road".equals(x.getStreetAddress()))
                        .findAny()
                        .orElse(null);
        Address postCode =
                addressList.stream()
                        .filter(x -> "38421-3292".equals(x.getPostalCode()))
                        .findAny()
                        .orElse(null);

        assertFalse(streetAddress.getStreetAddress().isEmpty());
        assertFalse(postCode.getPostalCode().isEmpty());

        assertEquals(2, (vcAttributes.get("name")).size());
        assertEquals(3, (vcAttributes.get("address")).size());
        assertEquals(2, (vcAttributes.get("birthDate")).size());

        ECDSAVerifier verifier = new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK));
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    void shouldDeduplicateSharedClaims() throws Exception {
        when(configurationService.getCredentialIssuer(CRI_ID)).thenReturn(credentialIssuerConfig);
        when(configurationService.getIpvTokenTtl()).thenReturn("900");
        when(configurationService.getCoreFrontCallbackUrl()).thenReturn("callbackUrl");
        when(configurationService.getAudienceForClients()).thenReturn(IPV_ISSUER);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(vcClaim(CREDENTIAL_ATTRIBUTES_1)),
                                generateVerifiableCredential(vcClaim(CREDENTIAL_ATTRIBUTES_1))));

        APIGatewayProxyRequestEvent input = createRequestEvent(emptyMap(), emptyMap());

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");
        JWEObject jweObject = JWEObject.parse(responseBody.get("request"));
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode sharedClaims = claimsSet.get(SHARED_CLAIMS);
        assertEquals(1, sharedClaims.get("name").size());
        assertEquals(2, sharedClaims.get("birthDate").size());
        assertEquals(2, sharedClaims.get("address").size());
    }

    @Test
    void shouldNotDeduplicateSharedClaimsIfFullNameDifferent() throws Exception {
        when(configurationService.getCredentialIssuer(CRI_ID)).thenReturn(credentialIssuerConfig);
        when(configurationService.getIpvTokenTtl()).thenReturn("900");
        when(configurationService.getCoreFrontCallbackUrl()).thenReturn("callbackUrl");
        when(configurationService.getAudienceForClients()).thenReturn(IPV_ISSUER);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(vcClaim(CREDENTIAL_ATTRIBUTES_2)),
                                generateVerifiableCredential(vcClaim(CREDENTIAL_ATTRIBUTES_3))));

        APIGatewayProxyRequestEvent input = createRequestEvent(emptyMap(), emptyMap());

        input.setPathParameters(Map.of("criId", CRI_ID));
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        Map<String, String> responseBody = getResponseBodyAsMap(response).get("cri");
        JWEObject jweObject = JWEObject.parse(responseBody.get("request"));
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode sharedClaims = claimsSet.get(SHARED_CLAIMS);
        assertEquals(2, sharedClaims.get("name").size());
    }

    private Map<String, Map<String, String>> getResponseBodyAsMap(
            APIGatewayProxyResponseEvent response) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), Map.class);
    }

    private APIGatewayProxyRequestEvent createRequestEvent(
            Map<String, String> body, Map<String, String> headers) {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody(
                body.keySet().stream()
                        .map(key -> key + "=" + body.get(key))
                        .collect(Collectors.joining("&")));
        input.setHeaders(headers);
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
