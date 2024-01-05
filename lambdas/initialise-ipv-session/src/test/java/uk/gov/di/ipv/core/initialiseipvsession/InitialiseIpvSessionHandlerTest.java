package uk.gov.di.ipv.core.initialiseipvsession;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;

@ExtendWith(MockitoExtension.class)
class InitialiseIpvSessionHandlerTest {

    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    public static final String CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.getInstance().generate();
    @Mock private Context mockContext;

    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private ConfigService mockConfigService;
    @Mock private KmsRsaDecrypter mockKmsRsaDecrypter;
    @Mock private JarValidator mockJarValidator;
    @Mock private AuditService mockAuditService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private VerifiableCredentialJwtValidator mockVerifiableCredentialJwtValidator;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
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
                        .claim("vtr", List.of("Cl.Cm.P2", "Cl.Cm.PCL200"))
                        .build();

        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
        signedJWT.sign(new ECDSASigner(getPrivateKey()));
        signedEncryptedJwt =
                TestFixtures.createJweObject(
                        new RSAEncrypter(RSAKey.parse(TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK)),
                        signedJWT);

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());

        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        clientOAuthSessionItem.setResponseType("test-type");
        clientOAuthSessionItem.setClientId("test-client");
        clientOAuthSessionItem.setRedirectUri("http://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        clientOAuthSessionItem.setVtr(List.of("Cl.Cm.P2", "Cl.Cm.PCL200"));
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest()
            throws JsonProcessingException, JarValidationException, ParseException, SqsException {
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
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

    @ParameterizedTest
    @MethodSource("getVtrTestValues")
    void shouldReturn400IfMissingVtr(List<String> vtrList)
            throws JsonProcessingException, InvalidKeySpecException, NoSuchAlgorithmException,
                    JOSEException, ParseException, HttpResponseExceptionWithErrorBody,
                    JarValidationException {
        JWTClaimsSet.Builder claimsSet =
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
                        .claim("client_id", "test-client");
        if (vtrList != null) {
            claimsSet.claim("vtr", vtrList);
        }
        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet.build());
        signedJWT.sign(new ECDSASigner(getPrivateKey()));
        signedEncryptedJwt =
                TestFixtures.createJweObject(
                        new RSAEncrypter(RSAKey.parse(TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK)),
                        signedJWT);

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

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_VTR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.MISSING_VTR.getMessage(), responseBody.get("message"));
    }

    private static Stream<Arguments> getVtrTestValues() {
        return Stream.of(
                Arguments.of((Object) null),
                Arguments.of(Collections.emptyList()),
                Arguments.of(List.of("", "")));
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
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
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

    @Test
    void shouldValidateAndStoreAnyInheritedIdentity()
            throws JsonProcessingException, JarValidationException, ParseException,
                    VerifiableCredentialException, InvalidKeySpecException,
                    NoSuchAlgorithmException, JOSEException {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .expirationTime(new Date(Instant.now().plusSeconds(1000).getEpochSecond()))
                        .issueTime(new Date())
                        .notBeforeTime(new Date())
                        .subject("test-user-id") // the inherited identity subject must equal this
                        .audience("test-audience")
                        .issuer("test-issuer")
                        .claim("response_type", "code")
                        .claim("redirect_uri", "http://example.com")
                        .claim("state", "test-state")
                        .claim("client_id", "test-client")
                        .claim("vtr", List.of("Cl.Cm.P2", "Cl.Cm.PCL200"))
                        .claim(
                                "https://vocab.account.gov.uk/v1/inheritedIdentityJWT",
                                getInheritedIdentityJWT().serialize())
                        .build();
        when(mockJarValidator.validateRequestJwt(any(), any())).thenReturn(claimsSet);
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY))
                .thenReturn(true); // Mock enabled inherited identity feature flag
        CriConfig testCriConfig =
                CriConfig.builder()
                        .componentId("test-component-id")
                        .signingKey("test-signing-key")
                        .build();
        when(mockConfigService.getCriConfig(HMRC_MIGRATION_CRI)).thenReturn(testCriConfig);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        verify(mockVerifiableCredentialJwtValidator, times(1))
                .validate(any(), eq(testCriConfig), eq("test-user-id"));
        verify(mockVerifiableCredentialService, times(1))
                .persistUserCredentials(any(), eq(HMRC_MIGRATION_CRI), eq("test-user-id"));
    }

    private static ECPrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }

    private static SignedJWT getInheritedIdentityJWT()
            throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException {
        SignedJWT inheritedIdentityJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        new JWTClaimsSet.Builder()
                                .subject("test-user-id")
                                .issuer("<https://oidc.hmrc.gov.uk/migration/v1>")
                                .notBeforeTime(new Date(1694430000L * 1000))
                                .claim("vot", "PCL200")
                                .claim("vtm", "<https://hmrc.gov.uk/trustmark>")
                                .claim(
                                        "vc",
                                        Map.of(
                                                "type",
                                                List.of(
                                                        "VerifiableCredential",
                                                        "InheritedIdentityCredential"),
                                                "credentialSubject",
                                                TestFixtures.CREDENTIAL_ATTRIBUTES_1))
                                .claim("evidence", List.of())
                                .build());
        inheritedIdentityJWT.sign(new ECDSASigner(getPrivateKey()));

        return inheritedIdentityJWT;
    }
}
