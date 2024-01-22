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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
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
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.CORE_IDENTITY_JWT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.INHERITED_IDENTITY_JWT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.PASSPORT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;

@ExtendWith(MockitoExtension.class)
class InitialiseIpvSessionHandlerTest {
    private static final CriConfig TEST_CRI_CONFIG =
            CriConfig.builder()
                    .componentId("test-component-id")
                    .signingKey("test-signing-key")
                    .build();
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    public static final String CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.getInstance().generate();
    public static final String RESPONSE_TYPE = "response_type";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String STATE = "state";
    public static final String CLIENT_ID = "client_id";
    public static final String VTR = "vtr";
    public static final String CLAIMS = "claims";
    public static final String USER_INFO = "userInfo";
    public static final String VALUES = "values";

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
    @Captor private ArgumentCaptor<SignedJWT> signedJWTArgumentCaptor;
    @Captor private ArgumentCaptor<IpvSessionItem> ipvSessionItemCaptor;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private static SignedJWT signedJWT;
    private static JWEObject signedEncryptedJwt;
    private static @Spy IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;
    private static JWTClaimsSet.Builder claimsBuilder =
            new JWTClaimsSet.Builder()
                    .expirationTime(new Date(Instant.now().plusSeconds(1000).getEpochSecond()))
                    .issueTime(new Date())
                    .notBeforeTime(new Date())
                    .subject("test-user-id")
                    .audience("test-audience")
                    .issuer("test-issuer")
                    .claim(RESPONSE_TYPE, "code")
                    .claim(REDIRECT_URI, "https://example.com")
                    .claim(STATE, "test-state")
                    .claim(CLIENT_ID, "test-client")
                    .claim(VTR, List.of("Cl.Cm.P2", "Cl.Cm.PCL200"))
                    .claim(
                            CLAIMS,
                            Map.of(
                                    USER_INFO,
                                    Map.of(
                                            ADDRESS_CLAIM_NAME, "test-address-claim",
                                            CORE_IDENTITY_JWT_CLAIM_NAME,
                                                    "test-core-identity-jwt-claim",
                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                    Map.of(VALUES, List.of()),
                                            PASSPORT_CLAIM_NAME, "test-passport-claim")));
    private static String serialisedInheritedIdentityJWT;

    @BeforeAll
    static void setUpBeforeAll()
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        serialisedInheritedIdentityJWT = getInheritedIdentityJWT().serialize();
    }

    @BeforeEach
    void setUp() throws Exception {
        signClaims(claimsBuilder);

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());

        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        clientOAuthSessionItem.setResponseType("test-type");
        clientOAuthSessionItem.setClientId("test-client");
        clientOAuthSessionItem.setRedirectUri("https://example.com");
        clientOAuthSessionItem.setState("test-state");
        clientOAuthSessionItem.setUserId("test-user-id");
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        clientOAuthSessionItem.setVtr(List.of("Cl.Cm.P2", "Cl.Cm.PCL200"));
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest()
            throws JsonProcessingException, JarValidationException, ParseException, SqsException {
        // Arrange
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

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
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
        // Arrange
        claimsBuilder.claim(VTR, vtrList);
        signClaims(claimsBuilder);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
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
        // Arrange
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfInvalidBody() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("invalid-body");
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingClientIdParameter() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, Object> sessionParams = Map.of("request", signedEncryptedJwt.serialize());

        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingRequestParameter() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, Object> sessionParams = Map.of("clientId", "test-client");

        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfRequestObjectNotEncrypted() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedJWT.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
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
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateErrorClientSessionDetails(
                        any(), any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenThrow(
                        new RecoverableJarValidationException(
                                new ErrorObject("server_error", "test error"),
                                "https://example.com",
                                "test-client",
                                "test-state",
                                "test-journey-id"));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
    }

    @Test
    void shouldValidateAndStoreAnyInheritedIdentity() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of(
                                                                VALUES,
                                                                List.of(
                                                                        serialisedInheritedIdentityJWT)))))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY))
                .thenReturn(true); // Mock enabled inherited identity feature flag
        when(mockConfigService.getCriConfig(HMRC_MIGRATION_CRI)).thenReturn(TEST_CRI_CONFIG);
        SignedJWT existingInheritedIdentityJwt = getInheritedIdentityJWT(VectorOfTrust.PCL200);
        when(mockVerifiableCredentialService.getVcStoreItem(HMRC_MIGRATION_CRI, "test-user-id"))
                .thenReturn(
                        new VcStoreItem(
                                "test-user-id",
                                HMRC_MIGRATION_CRI,
                                existingInheritedIdentityJwt.serialize(),
                                Instant.now(),
                                Instant.now()));
        when(mockUserIdentityService.getVot(any()))
                .thenReturn(VectorOfTrust.PCL200)
                .thenReturn(VectorOfTrust.PCL200);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        verify(mockVerifiableCredentialJwtValidator, times(1))
                .validate(
                        signedJWTArgumentCaptor.capture(), eq(TEST_CRI_CONFIG), eq("test-user-id"));
        assertEquals(
                serialisedInheritedIdentityJWT, signedJWTArgumentCaptor.getValue().serialize());

        verify(mockVerifiableCredentialService, times(1))
                .persistUserCredentials(
                        signedJWTArgumentCaptor.capture(),
                        eq(HMRC_MIGRATION_CRI),
                        eq("test-user-id"));
        assertEquals(
                serialisedInheritedIdentityJWT, signedJWTArgumentCaptor.getValue().serialize());

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemCaptor.capture());
        assertEquals(
                ipvSessionItemCaptor.getValue().getVcReceivedThisSession(),
                List.of(serialisedInheritedIdentityJWT));
    }

    @Test
    void shouldNotStoreInheritedIdentityWhenVotWeakerThanExisting() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of(
                                                                VALUES,
                                                                List.of(
                                                                        serialisedInheritedIdentityJWT)))))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        when(mockConfigService.getCriConfig(HMRC_MIGRATION_CRI)).thenReturn(TEST_CRI_CONFIG);
        SignedJWT existingInheritedIdentityJwt = getInheritedIdentityJWT(VectorOfTrust.PCL250);
        when(mockVerifiableCredentialService.getVcStoreItem(HMRC_MIGRATION_CRI, "test-user-id"))
                .thenReturn(
                        new VcStoreItem(
                                "test-user-id",
                                HMRC_MIGRATION_CRI,
                                existingInheritedIdentityJwt.serialize(),
                                Instant.now(),
                                Instant.now()));
        when(mockUserIdentityService.getVot(any()))
                .thenReturn(VectorOfTrust.PCL250)
                .thenReturn(VectorOfTrust.PCL200);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        verify(mockVerifiableCredentialJwtValidator, times(1))
                .validate(
                        signedJWTArgumentCaptor.capture(), eq(TEST_CRI_CONFIG), eq("test-user-id"));
        verify(mockUserIdentityService, times(2)).getVot(signedJWTArgumentCaptor.capture());

        List<SignedJWT> capturedArguments = signedJWTArgumentCaptor.getAllValues();
        assertEquals(3, capturedArguments.size());
        assertEquals(serialisedInheritedIdentityJWT, capturedArguments.get(0).serialize());
        // Used for comparing vots of inherited identities
        assertEquals(
                existingInheritedIdentityJwt.serialize(), capturedArguments.get(1).serialize());
        assertEquals(serialisedInheritedIdentityJWT, capturedArguments.get(2).serialize());

        verify(mockVerifiableCredentialService, times(0))
                .persistUserCredentials(any(), any(), any());
    }

    @Test
    void shouldHandleParseExceptionFromCheckingInheritedIdentityVotStrength() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of(
                                                                VALUES,
                                                                List.of(
                                                                        serialisedInheritedIdentityJWT)))))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        when(mockConfigService.getCriConfig(HMRC_MIGRATION_CRI)).thenReturn(TEST_CRI_CONFIG);
        SignedJWT existingInheritedIdentityJwt = getInheritedIdentityJWT(VectorOfTrust.PCL200);
        when(mockVerifiableCredentialService.getVcStoreItem(HMRC_MIGRATION_CRI, "test-user-id"))
                .thenReturn(
                        new VcStoreItem(
                                "test-user-id",
                                HMRC_MIGRATION_CRI,
                                existingInheritedIdentityJwt.serialize(),
                                Instant.now(),
                                Instant.now()));
        doThrow(new ParseException("", 0) {}).when(mockUserIdentityService).getVot(any());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldAllowRequestsThatDoNotIncludeAnInheritedIdentityJwtClaim() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(claimsBuilder.claim(CLAIMS, Map.of(USER_INFO, Map.of())).build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
    }

    @Test
    void shouldRecoverIfClaimsClaimCanNotBeConverted() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(claimsBuilder.claim(CLAIMS, Map.of("This", "shouldn't work?")).build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));
    }

    @Test
    void shouldRecoverIfInheritedIdentityJwtHasMultipleValues() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of(
                                                                VALUES,
                                                                List.of(
                                                                        serialisedInheritedIdentityJWT,
                                                                        serialisedInheritedIdentityJWT)))))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY))
                .thenReturn(true); // Mock enabled inherited identity feature flag

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));
    }

    @Test
    void shouldRecoverIfInheritedIdentityJwtHasNullValue() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of())))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY))
                .thenReturn(true); // Mock enabled inherited identity feature flag

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));
    }

    @Test
    void shouldRecoverIfInheritedIdentityJwtCanNotBeParsed() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of(VALUES, List.of("🌭")))))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));
    }

    @Test
    void shouldRecoverIfInheritedIdentityJwtFailsValidation() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of(
                                                                VALUES,
                                                                List.of(
                                                                        serialisedInheritedIdentityJWT)))))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        when(mockConfigService.getCriConfig(HMRC_MIGRATION_CRI)).thenReturn(TEST_CRI_CONFIG);
        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(mockVerifiableCredentialJwtValidator)
                .validate(any(SignedJWT.class), eq(TEST_CRI_CONFIG), eq("test-user-id"));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));
    }

    @Test
    void shouldRecoverIfInheritedIdentityJwtFailsToPersist() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(
                        claimsBuilder
                                .claim(
                                        CLAIMS,
                                        Map.of(
                                                USER_INFO,
                                                Map.of(
                                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                        Map.of(
                                                                VALUES,
                                                                List.of(
                                                                        serialisedInheritedIdentityJWT)))))
                                .build());
        when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        CriConfig testCriConfig =
                CriConfig.builder()
                        .componentId("test-component-id")
                        .signingKey("test-signing-key")
                        .build();
        when(mockConfigService.getCriConfig(HMRC_MIGRATION_CRI)).thenReturn(testCriConfig);
        SignedJWT existingInheritedIdentityJwt = getInheritedIdentityJWT(VectorOfTrust.PCL200);
        when(mockVerifiableCredentialService.getVcStoreItem(HMRC_MIGRATION_CRI, "test-user-id"))
                .thenReturn(
                        new VcStoreItem(
                                "test-user-id",
                                HMRC_MIGRATION_CRI,
                                existingInheritedIdentityJwt.serialize(),
                                Instant.now(),
                                Instant.now()));
        when(mockUserIdentityService.getVot(any()))
                .thenReturn(VectorOfTrust.PCL200)
                .thenReturn(VectorOfTrust.PCL200);
        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_SAVE_CREDENTIAL))
                .when(mockVerifiableCredentialService)
                .persistUserCredentials(
                        any(SignedJWT.class), eq("hmrcMigration"), eq("test-user-id"));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedEncryptedJwt.serialize());
        event.setBody(objectMapper.writeValueAsString(sessionParams));
        event.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(event, mockContext);

        // Assert
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));
    }

    private static void signClaims(JWTClaimsSet.Builder claimsBuilder)
            throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException,
                    HttpResponseExceptionWithErrorBody, ParseException {
        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsBuilder.build());
        signedJWT.sign(new ECDSASigner(getPrivateKey()));
        signedEncryptedJwt =
                TestFixtures.createJweObject(
                        new RSAEncrypter(RSAKey.parse(TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK)),
                        signedJWT);
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
        return getInheritedIdentityJWT(VectorOfTrust.PCL200);
    }

    private static SignedJWT getInheritedIdentityJWT(VectorOfTrust vot)
            throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException {
        SignedJWT inheritedIdentityJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        new JWTClaimsSet.Builder()
                                .subject("test-user-id")
                                .issuer("<https://oidc.hmrc.gov.uk/migration/v1>")
                                .notBeforeTime(new Date(1694430000L * 1000))
                                .claim("vot", vot.toString())
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
