package uk.gov.di.ipv.core.initialiseipvsession;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;

@ExtendWith(MockitoExtension.class)
class InitialiseIpvSessionHandlerTest {

    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    public static final String CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    @Mock private Context mockContext;

    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private ConfigService mockConfigService;
    @Mock private KmsRsaDecrypter mockKmsRsaDecrypter;
    @Mock private JarValidator mockJarValidator;
    @Mock private AuditService mockAuditService;
    @Mock private UserIdentityService mockUserIdentityService;
    @InjectMocks private InitialiseIpvSessionHandler initialiseIpvSessionHandler;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static SignedJWT signedJWT;
    private static JWEObject signedEncryptedJwt;
    private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() throws Exception {
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .expirationTime(new Date(Instant.now().plusSeconds(1000).getEpochSecond()))
                        .issueTime(new Date())
                        .notBeforeTime(new Date())
                        .subject("test-user-id")
                        .audience("test-audience")
                        .issuer("test-issuer")
                        .claim("response_type", "code")
                        .claim("redirect_uri", "http://example.com")
                        .claim("state", "test-state")
                        .claim("client_id", "test-client")
                        .build();

        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
        signedJWT.sign(new ECDSASigner(getPrivateKey()));
        signedEncryptedJwt =
                TestFixtures.createJweObject(
                        new RSAEncrypter(RSAKey.parse(TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK)),
                        signedJWT);

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());

        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        clientOAuthSessionItem.setResponseType("test-type");
        clientOAuthSessionItem.setClientId("test-client");
        clientOAuthSessionItem.setRedirectUri("http://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest()
            throws JsonProcessingException, JarValidationException, ParseException, SqsException {
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, auditEventCaptor.getValue().getEventName());
    }

    @Test
    void shouldReturn400IfMissingBody() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfInvalidBody() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("invalid-body");
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingClientIdParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, Object> sessionParams = Map.of("request", signedEncryptedJwt.serialize());

        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingRequestParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, Object> sessionParams = Map.of("clientId", "test-client");

        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfRequestObjectNotEncrypted() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedJWT.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturnIpvSessionIdWhenRecoverableErrorFound()
            throws JsonProcessingException, JarValidationException, ParseException {
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateErrorClientSessionDetails(
                        any(), any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenThrow(
                        new RecoverableJarValidationException(
                                new ErrorObject("server_error", "test error"),
                                "http://example.com",
                                "test-client",
                                "test-state",
                                "test-journey-id"));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
    }

    private static ECPrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
