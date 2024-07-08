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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.initialiseipvsession.domain.Essential;
import uk.gov.di.ipv.core.initialiseipvsession.exception.JarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.exception.RecoverableJarValidationException;
import uk.gov.di.ipv.core.initialiseipvsession.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.initialiseipvsession.validation.JarValidator;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionAccountIntervention;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedInheritedIdentity;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.config.FeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.helpers.TestVc;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.OAuth2Error.INVALID_REQUEST_OBJECT_CODE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsIpvJourneyStart.REPROVE_IDENTITY_KEY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ScopeConstants.REVERIFICATION;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.CORE_IDENTITY_JWT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.EVCS_ACCESS_TOKEN_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.INHERITED_IDENTITY_JWT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.PASSPORT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200NoEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250NoEvidence;

@ExtendWith(MockitoExtension.class)
class InitialiseIpvSessionHandlerTest {
    public static final String TEST_COMPONENT_ID = "test-component-id";
    public static final String TEST_SIGNING_KEY =
            "{\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}"; // pragma: allowlist secret
    public static final String TEST_USER_ID = "test-user-id";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final CriConfig TEST_CRI_CONFIG =
            CriConfig.builder().componentId(TEST_COMPONENT_ID).signingKey(TEST_SIGNING_KEY).build();
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
    private static final String INVALID_INHERITED_IDENTITY = "invalid_inherited_identity";
    private static final String INVALID_EVCS_ACCESS_TOKEN = "invalid_evcs_access_token";
    private static final APIGatewayProxyRequestEvent validEvent = new APIGatewayProxyRequestEvent();
    public static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    private static SignedJWT signedJWT;
    private static JWEObject signedEncryptedJwt;
    private static @Spy IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;
    private static VerifiableCredential PCL250_MIGRATION_VC;
    private static VerifiableCredential PCL200_MIGRATION_VC;

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private ConfigService mockConfigService;
    @Mock private KmsRsaDecrypter mockKmsRsaDecrypter;
    @Mock private JarValidator mockJarValidator;
    @Mock private AuditService mockAuditService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private VerifiableCredentialValidator mockVerifiableCredentialValidator;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private InitialiseIpvSessionHandler initialiseIpvSessionHandler;
    @Captor private ArgumentCaptor<String> stringArgumentCaptor;
    @Captor private ArgumentCaptor<VerifiableCredential> verifiableCredentialArgumentCaptor;
    @Captor private ArgumentCaptor<IpvSessionItem> ipvSessionItemCaptor;
    @Captor private ArgumentCaptor<ErrorObject> errorObjectArgumentCaptor;

    @BeforeAll
    static void setUpBeforeAll() throws Exception {
        PCL250_MIGRATION_VC = vcHmrcMigrationPCL250NoEvidence();
        PCL200_MIGRATION_VC = vcHmrcMigrationPCL200NoEvidence();

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
        clientOAuthSessionItem.setUserId(TEST_USER_ID);
        clientOAuthSessionItem.setGovukSigninJourneyId("test-journey-id");
        clientOAuthSessionItem.setVtr(List.of("Cl.Cm.P2", "Cl.Cm.PCL200"));
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest()
            throws JsonProcessingException, JarValidationException, ParseException, SqsException {
        ArgumentCaptor<String> evcsAccessTokenCaptor = ArgumentCaptor.forClass(String.class);
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
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

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, auditEventCaptor.getValue().getEventName());

        verify(mockClientOAuthSessionDetailsService)
                .generateClientSessionDetails(any(), any(), any(), evcsAccessTokenCaptor.capture());
        assertNull(evcsAccessTokenCaptor.getValue());
    }

    @Test
    void shouldReturnIpvSessionIdAndSendAuditEventWhenProvidedValidReproveRequest()
            throws JsonProcessingException, JarValidationException, ParseException, SqsException {
        ArgumentCaptor<String> evcsAccessTokenCaptor = ArgumentCaptor.forClass(String.class);
        // Arrange
        when(mockConfigService.enabled(any(FeatureFlag.class))).thenReturn(false);
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                        any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(getValidClaimsBuilder().claim(REPROVE_IDENTITY_KEY, true).build());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var capturedValues = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, capturedValues.get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_ACCOUNT_INTERVENTION_START,
                capturedValues.get(1).getEventName());

        AuditExtensionAccountIntervention extensions =
                (AuditExtensionAccountIntervention) capturedValues.get(1).getExtensions();
        assertEquals("reprove_identity", extensions.getType());
        assertNull(extensions.getSuccess());

        verify(mockClientOAuthSessionDetailsService)
                .generateClientSessionDetails(any(), any(), any(), evcsAccessTokenCaptor.capture());
        assertNull(evcsAccessTokenCaptor.getValue());
    }

    @Test
    void shouldRecoverIfEvcsEnabledButMissingEvcsAccesToken() throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
                .thenReturn(ipvSessionItem);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));

        verify(mockIpvSessionService, times(2))
                .generateIpvSession(
                        anyString(), errorObjectArgumentCaptor.capture(), isNull(), anyBoolean());
        var capturedErrorObject = errorObjectArgumentCaptor.getAllValues().get(1);
        assertEquals(INVALID_EVCS_ACCESS_TOKEN, capturedErrorObject.getCode());
        assertEquals(
                "Evcs access token jwt claim not received", capturedErrorObject.getDescription());
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest_andSaveEvcsAccessToken()
            throws JsonProcessingException, JarValidationException, ParseException, SqsException {
        ArgumentCaptor<String> evcsAccessTokenCaptor = ArgumentCaptor.forClass(String.class);

        var evcsAccessTokenClaims =
                Map.of(
                        USER_INFO,
                        Map.of(
                                INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                Map.of(VALUES, List.of(PCL200_MIGRATION_VC.getVcString())),
                                EVCS_ACCESS_TOKEN_CLAIM_NAME,
                                Map.of(VALUES, List.of(TEST_EVCS_ACCESS_TOKEN))));
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                        any(), any(), any(), any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(getValidClaimsBuilder().claim(CLAIMS, evcsAccessTokenClaims).build());
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, auditEventCaptor.getValue().getEventName());

        verify(mockClientOAuthSessionDetailsService)
                .generateClientSessionDetails(any(), any(), any(), evcsAccessTokenCaptor.capture());
        assertEquals(TEST_EVCS_ACCESS_TOKEN, evcsAccessTokenCaptor.getValue());
    }

    @ParameterizedTest
    @MethodSource("getEvcsAccessTokenClaimValuesAndMsg")
    void shouldRecoverIfEvcsAccessClaimsHasMultipleTokenValues(
            Map<String, Map<String, Map<String, List<String>>>> evcsAccessTokenClaims,
            String expectedMessage)
            throws Exception {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
                .thenReturn(ipvSessionItem);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(getValidClaimsBuilder().claim(CLAIMS, evcsAccessTokenClaims).build());

        // Act
        APIGatewayProxyResponseEvent response =
                initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

        // Assert
        Map<String, Object> responseBody =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        verify(mockClientOAuthSessionDetailsService)
                .generateErrorClientSessionDetails(
                        any(String.class),
                        eq("https://example.com"),
                        eq("test-client"),
                        eq("test-state"),
                        eq(null));

        verify(mockIpvSessionService, times(2))
                .generateIpvSession(
                        anyString(), errorObjectArgumentCaptor.capture(), isNull(), anyBoolean());
        var capturedErrorObject = errorObjectArgumentCaptor.getAllValues().get(1);
        assertEquals(INVALID_EVCS_ACCESS_TOKEN, capturedErrorObject.getCode());
        assertEquals(expectedMessage, capturedErrorObject.getDescription());
    }

    private static Stream<Arguments> getEvcsAccessTokenClaimValuesAndMsg() {
        Map<String, Map<String, Map<String, List<String>>>> testMultiAccessToken =
                Map.of(
                        USER_INFO,
                        Map.of(
                                INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                Map.of(VALUES, List.of(PCL200_MIGRATION_VC.getVcString())),
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
            throws JsonProcessingException, InvalidKeySpecException, NoSuchAlgorithmException,
                    JOSEException, ParseException, JarValidationException {
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

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_VTR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.MISSING_VTR.getMessage(), responseBody.get("message"));
    }

    @ParameterizedTest
    @MethodSource("getVtrTestValues")
    void shouldIpvSessionIdIfMissingVtrAndReverificationJourney(List<String> vtrList)
            throws JsonProcessingException, InvalidKeySpecException, NoSuchAlgorithmException,
                    JOSEException, ParseException, JarValidationException {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
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

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
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

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
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

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
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

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
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

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
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

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturnIpvSessionIdWhenRecoverableErrorFound()
            throws JsonProcessingException, JarValidationException, ParseException {
        // Arrange
        when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
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

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
    }

    @Nested
    @DisplayName("inherited identity tests")
    class InheritedIdentityTests {

        @BeforeEach
        void setUp() throws Exception {
            when(mockConfigService.enabled(CoreFeatureFlag.INHERITED_IDENTITY))
                    .thenReturn(true); // Mock enabled inherited identity feature flag
            when(mockIpvSessionService.generateIpvSession(any(), any(), any(), anyBoolean()))
                    .thenReturn(ipvSessionItem);
            when(mockClientOAuthSessionDetailsService.generateClientSessionDetails(
                            any(), any(), any(), any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldValidateAndStoreAnyInheritedIdentityWhenStrongerVotThanExisting()
                throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(
                                                                    VALUES,
                                                                    List.of(
                                                                            PCL250_MIGRATION_VC
                                                                                    .getVcString())))))
                                    .build());
            when(mockConfigService.getCriConfig(HMRC_MIGRATION.getId()))
                    .thenReturn(TEST_CRI_CONFIG);
            when(mockVerifiableCredentialValidator.parseAndValidate(
                            TEST_USER_ID,
                            HMRC_MIGRATION,
                            PCL250_MIGRATION_VC.getVcString(),
                            TEST_SIGNING_KEY,
                            TEST_COMPONENT_ID,
                            true))
                    .thenReturn(PCL250_MIGRATION_VC);
            when(mockVerifiableCredentialService.getVc(TEST_USER_ID, HMRC_MIGRATION.getId()))
                    .thenReturn(PCL200_MIGRATION_VC);
            when(mockUserIdentityService.getVot(any()))
                    .thenReturn(Vot.PCL200)
                    .thenReturn(Vot.PCL200);

            // Act
            initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            verify(mockVerifiableCredentialValidator, times(1))
                    .parseAndValidate(
                            eq(TEST_USER_ID),
                            eq(HMRC_MIGRATION),
                            stringArgumentCaptor.capture(),
                            eq(TEST_SIGNING_KEY),
                            eq(TEST_COMPONENT_ID),
                            eq(true));
            assertEquals(PCL250_MIGRATION_VC.getVcString(), stringArgumentCaptor.getValue());

            verify(mockVerifiableCredentialService, times(1))
                    .persistUserCredentials(verifiableCredentialArgumentCaptor.capture());
            assertEquals(PCL250_MIGRATION_VC, verifiableCredentialArgumentCaptor.getValue());

            verify(mockIpvSessionService).updateIpvSession(ipvSessionItemCaptor.capture());
            assertTrue(ipvSessionItem.isInheritedIdentityReceivedThisSession());
        }

        @Test
        void shouldValidateAndStoreAnyInheritedIdentityWhenNoExistingIdentity() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(
                                                                    VALUES,
                                                                    List.of(
                                                                            PCL200_MIGRATION_VC
                                                                                    .getVcString())))))
                                    .build());
            when(mockConfigService.getCriConfig(HMRC_MIGRATION.getId()))
                    .thenReturn(TEST_CRI_CONFIG);
            when(mockVerifiableCredentialValidator.parseAndValidate(
                            TEST_USER_ID,
                            HMRC_MIGRATION,
                            PCL200_MIGRATION_VC.getVcString(),
                            TEST_SIGNING_KEY,
                            TEST_COMPONENT_ID,
                            true))
                    .thenReturn(PCL200_MIGRATION_VC);
            when(mockVerifiableCredentialService.getVc(TEST_USER_ID, HMRC_MIGRATION.getId()))
                    .thenReturn(null);

            // Act
            initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            verify(mockVerifiableCredentialValidator, times(1))
                    .parseAndValidate(
                            eq(TEST_USER_ID),
                            eq(HMRC_MIGRATION),
                            stringArgumentCaptor.capture(),
                            eq(TEST_SIGNING_KEY),
                            eq(TEST_COMPONENT_ID),
                            eq(true));
            assertEquals(PCL200_MIGRATION_VC.getVcString(), stringArgumentCaptor.getValue());

            verify(mockVerifiableCredentialService, times(1))
                    .persistUserCredentials(verifiableCredentialArgumentCaptor.capture());
            assertEquals(PCL200_MIGRATION_VC, verifiableCredentialArgumentCaptor.getValue());

            verify(mockIpvSessionService).updateIpvSession(ipvSessionItemCaptor.capture());
            assertTrue(ipvSessionItem.isInheritedIdentityReceivedThisSession());
        }

        @Test
        void shouldSendAuditEventForIpvInheritedIdentityVcReceived() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(
                                                                    VALUES,
                                                                    List.of(
                                                                            PCL200_MIGRATION_VC
                                                                                    .getVcString())))))
                                    .build());
            when(mockConfigService.getCriConfig(HMRC_MIGRATION.getId()))
                    .thenReturn(TEST_CRI_CONFIG);
            when(mockVerifiableCredentialValidator.parseAndValidate(
                            TEST_USER_ID,
                            HMRC_MIGRATION,
                            PCL200_MIGRATION_VC.getVcString(),
                            TEST_SIGNING_KEY,
                            TEST_COMPONENT_ID,
                            true))
                    .thenReturn(PCL200_MIGRATION_VC);
            when(mockVerifiableCredentialService.getVc(TEST_USER_ID, HMRC_MIGRATION.getId()))
                    .thenReturn(null);

            // Act
            initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
            verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());

            var inheritedIdentityAuditEvent = auditEventCaptor.getAllValues().get(0);
            assertEquals(
                    AuditEventTypes.IPV_INHERITED_IDENTITY_VC_RECEIVED,
                    inheritedIdentityAuditEvent.getEventName());
            var extension = (AuditExtensionsVcEvidence) inheritedIdentityAuditEvent.getExtensions();
            var expectedAge =
                    Period.between(LocalDate.parse(TestVc.DEFAULT_DOB), LocalDate.now()).getYears();
            var expectedExtension =
                    new AuditExtensionsVcEvidence(
                            "https://orch.stubs.account.gov.uk/migration/v1",
                            OBJECT_MAPPER.valueToTree(List.of()),
                            null,
                            Vot.PCL200,
                            Boolean.TRUE,
                            expectedAge);
            assertEquals(expectedExtension, extension);
            var restricted =
                    (AuditRestrictedInheritedIdentity) inheritedIdentityAuditEvent.getRestricted();
            assertEquals(
                    "[{\"nameParts\":[{\"value\":\"KENNETH\",\"type\":\"GivenName\"},{\"value\":\"DECERQUEIRA\",\"type\":\"FamilyName\"}]}]",
                    OBJECT_MAPPER.writeValueAsString(restricted.name()));
            assertEquals(
                    "[{\"value\":\"1965-07-08\"}]",
                    OBJECT_MAPPER.writeValueAsString(restricted.birthDate()));
            assertEquals(
                    "[{\"personalNumber\":\"AB123456C\"}]",
                    OBJECT_MAPPER.writeValueAsString(restricted.socialSecurityRecord()));

            assertEquals(
                    AuditEventTypes.IPV_JOURNEY_START,
                    auditEventCaptor.getAllValues().get(1).getEventName());
        }

        @Test
        void shouldNotStoreInheritedIdentityWhenVotWeakerThanExisting() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(
                                                                    VALUES,
                                                                    List.of(
                                                                            PCL200_MIGRATION_VC
                                                                                    .getVcString())))))
                                    .build());
            when(mockConfigService.getCriConfig(HMRC_MIGRATION.getId()))
                    .thenReturn(TEST_CRI_CONFIG);
            when(mockVerifiableCredentialValidator.parseAndValidate(
                            TEST_USER_ID,
                            HMRC_MIGRATION,
                            PCL200_MIGRATION_VC.getVcString(),
                            TEST_SIGNING_KEY,
                            TEST_COMPONENT_ID,
                            true))
                    .thenReturn(PCL200_MIGRATION_VC);
            when(mockVerifiableCredentialService.getVc(TEST_USER_ID, HMRC_MIGRATION.getId()))
                    .thenReturn(PCL250_MIGRATION_VC);
            when(mockUserIdentityService.getVot(any()))
                    .thenReturn(Vot.PCL250)
                    .thenReturn(Vot.PCL200);

            // Act
            initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            verify(mockVerifiableCredentialValidator, times(1))
                    .parseAndValidate(
                            eq(TEST_USER_ID),
                            eq(HMRC_MIGRATION),
                            stringArgumentCaptor.capture(),
                            eq(TEST_SIGNING_KEY),
                            eq(TEST_COMPONENT_ID),
                            eq(true));
            assertEquals(PCL200_MIGRATION_VC.getVcString(), stringArgumentCaptor.getValue());

            verify(mockUserIdentityService, times(2))
                    .getVot(verifiableCredentialArgumentCaptor.capture());

            List<VerifiableCredential> capturedArguments =
                    verifiableCredentialArgumentCaptor.getAllValues();
            assertEquals(2, capturedArguments.size());
            assertEquals(PCL250_MIGRATION_VC, capturedArguments.get(0));
            assertEquals(PCL200_MIGRATION_VC, capturedArguments.get(1));

            verify(mockVerifiableCredentialService, times(0)).persistUserCredentials(any());
        }

        @Test
        void shouldHandleUnrecognisedVotExceptionFromSendingAuditEvent() throws Exception {
            // Arrange
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(
                                                                    VALUES,
                                                                    List.of(
                                                                            PCL200_MIGRATION_VC
                                                                                    .getVcString())))))
                                    .build());

            when(mockConfigService.getCriConfig(HMRC_MIGRATION.getId()))
                    .thenReturn(TEST_CRI_CONFIG);
            when(mockVerifiableCredentialValidator.parseAndValidate(
                            TEST_USER_ID,
                            HMRC_MIGRATION,
                            PCL200_MIGRATION_VC.getVcString(),
                            TEST_SIGNING_KEY,
                            TEST_COMPONENT_ID,
                            true))
                    .thenReturn(PCL200_MIGRATION_VC);
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);

            // Act
            APIGatewayProxyResponseEvent response;
            try (MockedStatic<VcHelper> vcHelper = mockStatic(VcHelper.class)) {
                vcHelper.when(() -> VcHelper.getVcVot(any()))
                        .thenThrow(new UnrecognisedVotException(""));
                response = initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);
            }

            // Assert
            Map<String, Object> responseBody =
                    OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

            assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

            verify(mockIpvSessionService, times(2))
                    .generateIpvSession(
                            anyString(),
                            errorObjectArgumentCaptor.capture(),
                            isNull(),
                            anyBoolean());
            var capturedErrorObject = errorObjectArgumentCaptor.getAllValues().get(1);
            assertEquals(INVALID_INHERITED_IDENTITY, capturedErrorObject.getCode());
            assertEquals(
                    "Inherited identity JWT failed to validate",
                    capturedErrorObject.getDescription());
        }

        @Test
        void shouldAllowRequestsThatDoNotIncludeAnInheritedIdentityJwtClaim() throws Exception {
            // Arrange
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(CLAIMS, Map.of(USER_INFO, Map.of()))
                                    .build());
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);

            // Act
            APIGatewayProxyResponseEvent response =
                    initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            Map<String, Object> responseBody =
                    OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

            assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));

            ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
            verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_JOURNEY_START, auditEventCaptor.getValue().getEventName());
        }

        @Test
        void shouldRecoverIfClaimsClaimCanNotBeConverted() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(CLAIMS, Map.of("This", "shouldn't work?"))
                                    .build());

            // Act
            APIGatewayProxyResponseEvent response =
                    initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            Map<String, Object> responseBody =
                    OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

            assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
            verify(mockClientOAuthSessionDetailsService)
                    .generateErrorClientSessionDetails(
                            any(String.class),
                            eq("https://example.com"),
                            eq("test-client"),
                            eq("test-state"),
                            eq(null));

            verify(mockIpvSessionService, times(2))
                    .generateIpvSession(
                            anyString(),
                            errorObjectArgumentCaptor.capture(),
                            isNull(),
                            anyBoolean());
            var capturedErrorObject = errorObjectArgumentCaptor.getAllValues().get(1);
            assertEquals(INVALID_REQUEST_OBJECT_CODE, capturedErrorObject.getCode());
            assertEquals(
                    "Claims cannot be parsed to JarClaims", capturedErrorObject.getDescription());
        }

        @Test
        void shouldRecoverIfInheritedIdentityJwtHasMultipleValues() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(
                                                                    VALUES,
                                                                    List.of(
                                                                            PCL200_MIGRATION_VC
                                                                                    .getVcString(),
                                                                            PCL200_MIGRATION_VC
                                                                                    .getVcString())))))
                                    .build());

            // Act
            APIGatewayProxyResponseEvent response =
                    initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            Map<String, Object> responseBody =
                    OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

            assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
            verify(mockClientOAuthSessionDetailsService)
                    .generateErrorClientSessionDetails(
                            any(String.class),
                            eq("https://example.com"),
                            eq("test-client"),
                            eq("test-state"),
                            eq(null));

            verify(mockIpvSessionService, times(2))
                    .generateIpvSession(
                            anyString(),
                            errorObjectArgumentCaptor.capture(),
                            isNull(),
                            anyBoolean());
            var capturedErrorObject = errorObjectArgumentCaptor.getAllValues().get(1);
            assertEquals(INVALID_INHERITED_IDENTITY, capturedErrorObject.getCode());
            assertEquals(
                    "2 inherited identity jwts received - one expected",
                    capturedErrorObject.getDescription());
        }

        @Test
        void shouldRecoverIfInheritedIdentityJwtHasNullValue() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of())))
                                    .build());

            // Act
            APIGatewayProxyResponseEvent response =
                    initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            Map<String, Object> responseBody =
                    OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

            assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
            verify(mockClientOAuthSessionDetailsService)
                    .generateErrorClientSessionDetails(
                            any(String.class),
                            eq("https://example.com"),
                            eq("test-client"),
                            eq("test-state"),
                            eq(null));

            verify(mockIpvSessionService, times(2))
                    .generateIpvSession(
                            anyString(),
                            errorObjectArgumentCaptor.capture(),
                            isNull(),
                            anyBoolean());
            var capturedErrorObject = errorObjectArgumentCaptor.getAllValues().get(1);
            assertEquals(INVALID_INHERITED_IDENTITY, capturedErrorObject.getCode());
            assertEquals(
                    "Inherited identity jwt claim received but value is null",
                    capturedErrorObject.getDescription());
        }

        @Test
        void shouldRecoverIfInheritedIdentityJwtFailsToParseAndValidate() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(VALUES, List.of("🌭")))))
                                    .build());
            when(mockConfigService.getCriConfig(HMRC_MIGRATION.getId()))
                    .thenReturn(TEST_CRI_CONFIG);
            when(mockVerifiableCredentialValidator.parseAndValidate(
                            TEST_USER_ID,
                            HMRC_MIGRATION,
                            "🌭",
                            TEST_CRI_CONFIG.getSigningKey(),
                            TEST_CRI_CONFIG.getComponentId(),
                            true))
                    .thenThrow(
                            new VerifiableCredentialException(
                                    HTTPResponse.SC_SERVER_ERROR,
                                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS));

            // Act
            APIGatewayProxyResponseEvent response =
                    initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            Map<String, Object> responseBody =
                    OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

            assertEquals(HttpStatus.SC_OK, response.getStatusCode());
            assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
            verify(mockClientOAuthSessionDetailsService)
                    .generateErrorClientSessionDetails(
                            any(String.class),
                            eq("https://example.com"),
                            eq("test-client"),
                            eq("test-state"),
                            eq(null));

            verify(mockIpvSessionService, times(2))
                    .generateIpvSession(
                            anyString(),
                            errorObjectArgumentCaptor.capture(),
                            isNull(),
                            anyBoolean());
            var capturedErrorObject = errorObjectArgumentCaptor.getAllValues().get(1);
            assertEquals(INVALID_INHERITED_IDENTITY, capturedErrorObject.getCode());
            assertEquals(
                    "Inherited identity JWT failed to validate",
                    capturedErrorObject.getDescription());
        }

        @Test
        void shouldRecoverIfInheritedIdentityJwtFailsToPersist() throws Exception {
            // Arrange
            when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
            when(mockConfigService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
            when(mockJarValidator.validateRequestJwt(any(), any()))
                    .thenReturn(
                            getValidClaimsBuilder()
                                    .claim(
                                            CLAIMS,
                                            Map.of(
                                                    USER_INFO,
                                                    Map.of(
                                                            INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                                            Map.of(
                                                                    VALUES,
                                                                    List.of(
                                                                            PCL200_MIGRATION_VC
                                                                                    .getVcString())))))
                                    .build());
            when(mockConfigService.getCriConfig(HMRC_MIGRATION.getId()))
                    .thenReturn(TEST_CRI_CONFIG);
            when(mockVerifiableCredentialValidator.parseAndValidate(
                            TEST_USER_ID,
                            HMRC_MIGRATION,
                            PCL200_MIGRATION_VC.getVcString(),
                            TEST_SIGNING_KEY,
                            TEST_COMPONENT_ID,
                            true))
                    .thenReturn(PCL200_MIGRATION_VC);
            when(mockVerifiableCredentialService.getVc(TEST_USER_ID, HMRC_MIGRATION.getId()))
                    .thenReturn(PCL200_MIGRATION_VC);
            when(mockUserIdentityService.getVot(any()))
                    .thenReturn(Vot.PCL200)
                    .thenReturn(Vot.PCL200);
            doThrow(
                            new VerifiableCredentialException(
                                    HTTPResponse.SC_SERVER_ERROR,
                                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL))
                    .when(mockVerifiableCredentialService)
                    .persistUserCredentials(any());

            // Act
            APIGatewayProxyResponseEvent response =
                    initialiseIpvSessionHandler.handleRequest(validEvent, mockContext);

            // Assert
            Map<String, Object> responseBody =
                    OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

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
                .claim(VTR, List.of("P2", "PCL200"))
                .claim(SCOPE, "openid")
                .claim(
                        CLAIMS,
                        Map.of(
                                USER_INFO,
                                Map.of(
                                        ADDRESS_CLAIM_NAME,
                                        new Essential(true),
                                        CORE_IDENTITY_JWT_CLAIM_NAME,
                                        new Essential(true),
                                        INHERITED_IDENTITY_JWT_CLAIM_NAME,
                                        Map.of(VALUES, List.of()),
                                        PASSPORT_CLAIM_NAME,
                                        new Essential(true))));
    }
}
