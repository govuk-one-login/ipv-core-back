package uk.gov.di.ipv.core.session;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.JarValidationException;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.KmsRsaDecrypter;
import uk.gov.di.ipv.core.library.validation.JarValidator;

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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;

@ExtendWith(MockitoExtension.class)
class IpvSessionStartHandlerTest {

    @Mock private Context mockContext;

    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private KmsRsaDecrypter mockKmsRsaDecrypter;
    @Mock private JarValidator mockJarValidator;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private IpvSessionStartHandler ipvSessionStartHandler;
    private SignedJWT signedJWT;

    @BeforeEach
    void setUp() throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        ipvSessionStartHandler =
                new IpvSessionStartHandler(
                        mockIpvSessionService,
                        mockConfigurationService,
                        mockKmsRsaDecrypter,
                        mockJarValidator);

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
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest()
            throws JsonProcessingException, JarValidationException, ParseException {
        String ipvSessionId = UUID.randomUUID().toString();
        when(mockIpvSessionService.generateIpvSession(any())).thenReturn(ipvSessionId);
        when(mockJarValidator.validateRequestJwt(any(), any()))
                .thenReturn(signedJWT.getJWTClaimsSet());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client",
                        "https://example.com",
                        "test-scope",
                        "test-state",
                        false,
                        signedJWT.serialize());
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionId, responseBody.get("ipvSessionId"));
    }

    @Test
    void shouldReturn400IfMissingBody() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

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

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingResponseTypeParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        null,
                        "test-client-id",
                        "https://example.com",
                        "test-scope",
                        "test-state",
                        false,
                        signedJWT.serialize());
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

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

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        null,
                        "https://example.com",
                        "test-scope",
                        "test-state",
                        false,
                        signedJWT.serialize());
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingRedirectUriParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client-id",
                        null,
                        "test-scope",
                        "test-state",
                        false,
                        signedJWT.serialize());
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingScopeParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client-id",
                        "https://example.com",
                        null,
                        "test-state",
                        false,
                        null);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingStateParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client-id",
                        "https://example.com",
                        "test-scope",
                        null,
                        false,
                        null);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
