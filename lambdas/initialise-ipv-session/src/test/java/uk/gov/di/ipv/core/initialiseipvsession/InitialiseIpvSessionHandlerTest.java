package uk.gov.di.ipv.core.initialiseipvsession;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.initialiseipvsession.domain.Essential;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.config.FeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.CORE_IDENTITY_JWT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.EVCS_ACCESS_TOKEN_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.PASSPORT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;

@ExtendWith(MockitoExtension.class)
class InitialiseIpvSessionHandlerTest {
    public static final String TEST_COMPONENT_ID = "test-component-id";
    public static final String TEST_SIGNING_KEY =
            "{\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}"; // pragma: allowlist secret
    public static final String TEST_USER_ID = "test-user-id";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final String RESPONSE_TYPE = "response_type";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String STATE = "state";
    private static final String CLIENT_ID = "client_id";
    private static final String VTR = "vtr";
    private static final String CLAIMS = "claims";
    private static final String USER_INFO = "userinfo";
    private static final String VALUES = "values";
    private static final String SCOPE = "scope";
    private static final String INVALID_EVCS_ACCESS_TOKEN = "invalid_evcs_access_token";
    private static final APIGatewayProxyRequestEvent validEvent = new APIGatewayProxyRequestEvent();
    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    private static SignedJWT signedJWT;
    private static JWEObject signedEncryptedJwt;
    private static @Spy IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Captor private ArgumentCaptor<String> stringArgumentCaptor;
    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private ConfigService mockConfigService;
    @Mock private JarValidator mockJarValidator;
    @Mock private AuditService mockAuditService;
    @InjectMocks private InitialiseIpvSessionHandler initialiseIpvSessionHandler;

    @Captor private ArgumentCaptor<ErrorObject> errorObjectArgumentCaptor;

    @BeforeAll
    static void setUpBeforeAll() throws Exception {
        signedJWT = getSignedJWT(getValidClaimsBuilder());
        signedEncryptedJwt = getJwe(signedJWT);

        validEvent.setBody(
                OBJECT_MAPPER.writeValueAsString(
                        Map.of(
                                "clientId",
                                "test-client",
                                "request",
                                signedEncryptedJwt.serialize())));
        validEvent.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));
    }

    @BeforeEach
    void setUp() {
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
        clientOAuthSessionItem.setUserId(TEST_USER_ID);
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        clientOAuthSessionItem.setVtr(List.of("Cl.Cm.P2"));
        clientOAuthSessionItem.setEvcsAccessToken(TEST_EVCS_ACCESS_TOKEN);
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest()
            throws JsonProcessingException, JarValidationException, ParseException {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                        any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, auditEventCaptor.getValue().getEventName());

        verify(mockClientOAuthSessionDetailsService)
                .generateClientSessionDetails(any(), any(), any(), stringArgumentCaptor.capture());
        assertEquals(TEST_EVCS_ACCESS_TOKEN, stringArgumentCaptor.getValue());
    }

    @Test
    void shouldReturnIpvSessionIdGivenValidReverificationRequest() throws Exception {
        // Arrange
        signedJWT = getSignedJWT(getValidClaimsBuilder("reverification"));
        signedEncryptedJwt = getJwe(signedJWT);

        validEvent.setBody(
                OBJECT_MAPPER.writeValueAsString(
                        Map.of(
                                "clientId",
                                "test-client",
                                "request",
                                signedEncryptedJwt.serialize())));
        validEvent.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        when(mockConfigService.enabled(MFA_RESET)).thenReturn(Boolean.TRUE);
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                        any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var auditEventsCaptured = auditEventCaptor.getAllValues();

        assertEquals(AuditEventTypes.IPV_JOURNEY_START, auditEventsCaptured.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_REVERIFY_START, auditEventsCaptured.get(1).getEventName());

        verify(mockClientOAuthSessionDetailsService)
                .generateClientSessionDetails(any(), any(), any(), stringArgumentCaptor.capture());
        assertEquals(TEST_EVCS_ACCESS_TOKEN, stringArgumentCaptor.getValue());
    }

    @Test
    void shouldReturnIpvSessionIdAndSendAuditEventWhenProvidedValidReproveRequest()
            throws JsonProcessingException, JarValidationException, ParseException {
        // Arrange
        clientOAuthSessionItem.setReproveIdentity(true);
        when(mockConfigService.enabled(any(FeatureFlag.class))).thenReturn(false);
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                        any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        var capturedValues = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, capturedValues.getFirst().getEventName());

        verify(mockClientOAuthSessionDetailsService)
                .generateClientSessionDetails(any(), any(), any(), stringArgumentCaptor.capture());
        assertEquals(TEST_EVCS_ACCESS_TOKEN, stringArgumentCaptor.getValue());
    }

    @Test
    void shouldRecoverIfMissingEvcsAccessToken() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(ipvSessionItem);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        var evcsAccessTokenClaims = Map.of(USER_INFO, Map.of());
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(getValidClaimsBuilder().claim(CLAIMS, evcsAccessTokenClaims).build());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));

        verify(mockIpvSessionService)
                .generateIpvSession(
                        anyString(),
                        errorObjectArgumentCaptor.capture(),
                        isNull(),
                        anyBoolean(),
                        any());
        var capturedErrorObject = errorObjectArgumentCaptor.getValue();
        assertEquals(INVALID_EVCS_ACCESS_TOKEN, capturedErrorObject.getCode());
        assertEquals(
                "Evcs access token jwt claim not received", capturedErrorObject.getDescription());
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest_andSaveEvcsAccessToken()
            throws JsonProcessingException, JarValidationException, ParseException {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                        any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, auditEventCaptor.getValue().getEventName());

        verify(mockClientOAuthSessionDetailsService)
                .generateClientSessionDetails(any(), any(), any(), stringArgumentCaptor.capture());
        assertEquals(TEST_EVCS_ACCESS_TOKEN, stringArgumentCaptor.getValue());
    }

    @ParameterizedTest
    @MethodSource("getEvcsAccessTokenClaimValuesAndMsg")
    void shouldRecoverIfEvcsAccessClaimsHasMultipleTokenValues(
            Map<String, Map<String, Map<String, List<String>>>> evcsAccessTokenClaims,
            String expectedMessage)
            throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(ipvSessionItem);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(getValidClaimsBuilder().claim(CLAIMS, evcsAccessTokenClaims).build());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));

        verify(mockIpvSessionService)
                .generateIpvSession(
                        anyString(),
                        errorObjectArgumentCaptor.capture(),
                        isNull(),
                        anyBoolean(),
                        any());
        var capturedErrorObject = errorObjectArgumentCaptor.getValue();
        assertEquals(INVALID_EVCS_ACCESS_TOKEN, capturedErrorObject.getCode());
        assertEquals(expectedMessage, capturedErrorObject.getDescription());
    }

    private static Stream<Arguments> getEvcsAccessTokenClaimValuesAndMsg() {
        Map<String, Map<String, Map<String, List<String>>>> testMultiAccessToken =
                Map.of(
                        USER_INFO,
                        Map.of(
                                EVCS_ACCESS_TOKEN_CLAIM_NAME,
                                Map.of(
                                        VALUES,
                                        List.of(
                                                TEST_EVCS_ACCESS_TOKEN,
                                                "test_multi_access_token"))));
        Map<String, List<String>> values = new HashMap<>();
        values.put(VALUES, null);
        return Stream.of(
                Arguments.of(testMultiAccessToken, "2 EVCS access token received - one expected"),
                Arguments.of(
                        Map.of(USER_INFO, Map.of()), "Evcs access token jwt claim not received"),
                Arguments.of(
                        Map.of(USER_INFO, Map.of(EVCS_ACCESS_TOKEN_CLAIM_NAME, values)),
                        "Evcs access token jwt claim received but value is null"));
    }

    @ParameterizedTest
    @MethodSource("getVtrTestValues")
    void shouldReturn400IfMissingVtr(List<String> vtrList)
            throws JsonProcessingException,
                    InvalidKeySpecException,
                    NoSuchAlgorithmException,
                    JOSEException,
                    ParseException,
                    JarValidationException {
        // Arrange
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(true);
        var missingVtrClaimsBuilder = getValidClaimsBuilder();
        missingVtrClaimsBuilder.claim(VTR, vtrList);
        var missingVtrSignedJwt = getSignedJWT(missingVtrClaimsBuilder);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(missingVtrSignedJwt.getJWTClaimsSet());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_VTR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.MISSING_VTR.getMessage(), responseBody.get("message"));
    }

    @ParameterizedTest
    @MethodSource("getVtrTestValues")
    void shouldIpvSessionIdIfMissingVtrAndReverificationJourney(List<String> vtrList)
            throws JsonProcessingException,
                    InvalidKeySpecException,
                    NoSuchAlgorithmException,
                    JOSEException,
                    ParseException,
                    JarValidationException {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                        any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());

        when(mockConfigService.enabled(MFA_RESET)).thenReturn(true);
        var missingVtrClaimsBuilder = getValidClaimsBuilder();
        missingVtrClaimsBuilder.claim(VTR, vtrList);
        missingVtrClaimsBuilder.claim(SCOPE, REVERIFICATION);
        var missingVtrSignedJwt = getSignedJWT(missingVtrClaimsBuilder);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(missingVtrSignedJwt.getJWTClaimsSet());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
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
        APIGatewayProxyRequestEvent missingBodyEvent = new APIGatewayProxyRequestEvent();
        missingBodyEvent.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(missingBodyEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfInvalidBody() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent invalidBodyEvent = new APIGatewayProxyRequestEvent();
        invalidBodyEvent.setBody("invalid-body");
        invalidBodyEvent.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(invalidBodyEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingClientIdParameter() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent missingClientIdEvent = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams = Map.of("request", signedEncryptedJwt.serialize());
        missingClientIdEvent.setBody(OBJECT_MAPPER.writeValueAsString(sessionParams));
        missingClientIdEvent.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(missingClientIdEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingRequestParameter() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent missingRequestEvent = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams = Map.of("clientId", "test-client");
        missingRequestEvent.setBody(OBJECT_MAPPER.writeValueAsString(sessionParams));
        missingRequestEvent.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(missingRequestEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfRequestObjectNotEncrypted() throws JsonProcessingException {
        // Arrange
        APIGatewayProxyRequestEvent unencryptedRequestEvent = new APIGatewayProxyRequestEvent();
        Map<String, Object> sessionParams =
                Map.of("clientId", "test-client", "request", signedJWT.serialize());
        unencryptedRequestEvent.setBody(OBJECT_MAPPER.writeValueAsString(sessionParams));
        unencryptedRequestEvent.setHeaders(Map.of("ip-address", TEST_IP_ADDRESS));

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(unencryptedRequestEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturnIpvSessionIdWhenRecoverableErrorFound()
            throws JsonProcessingException, JarValidationException, ParseException {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean(), any()))
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

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatusCode.OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() {
        // Arrange
        doThrow(new RuntimeException("Test error")).when(mockConfigService).setFeatureSet(any());

        var logCollector = LogCollector.getLogCollectorFor(InitialiseIpvSessionHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> initialiseIpvSessionHandler.handleRequest(validEvent, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().getFirst();
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private static SignedJWT getSignedJWT(JWTClaimsSet.Builder claimsBuilder)
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        var signedClaimsJwt =
                new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsBuilder.build());
        signedClaimsJwt.sign(new ECDSASigner(getPrivateKey()));
        return signedClaimsJwt;
    }

    private static JWEObject getJwe(SignedJWT signedJwt)
            throws JOSEException, HttpResponseExceptionWithErrorBody, ParseException {
        return TestFixtures.createJweObject(
                new RSAEncrypter(RSAKey.parse(TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK)), signedJwt);
    }

    private static ECPrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }

    private static JWTClaimsSet.Builder getValidClaimsBuilder() {
        return getValidClaimsBuilder("openid");
    }

    private static JWTClaimsSet.Builder getValidClaimsBuilder(String scope) {
        return new JWTClaimsSet.Builder()
                .expirationTime(new Date(Instant.now().plusSeconds(1000).getEpochSecond()))
                .issueTime(new Date())
                .notBeforeTime(new Date())
                .subject(TEST_USER_ID)
                .audience("test-audience")
                .issuer("test-issuer")
                .claim(RESPONSE_TYPE, "code")
                .claim(REDIRECT_URI, "https://example.com")
                .claim(STATE, "test-state")
                .claim(CLIENT_ID, "test-client")
                .claim(VTR, List.of("P2"))
                .claim(SCOPE, scope)
                .claim(
                        CLAIMS,
                        Map.of(
                                USER_INFO,
                                Map.of(
                                        ADDRESS_CLAIM_NAME,
                                        new Essential(true),
                                        CORE_IDENTITY_JWT_CLAIM_NAME,
                                        new Essential(true),
                                        PASSPORT_CLAIM_NAME,
                                        new Essential(true),
                                        EVCS_ACCESS_TOKEN_CLAIM_NAME,
                                        Map.of(VALUES, List.of(TEST_EVCS_ACCESS_TOKEN)))));
    }
}
