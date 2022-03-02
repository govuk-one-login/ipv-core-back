package uk.gov.di.ipv.core.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.helpers.KmsSigner;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.sharedattributes.SharedAttributesHandler.CLAIMS_CLAIM;
import static uk.gov.di.ipv.core.sharedattributes.SharedAttributesHandler.VC_HTTP_API_CLAIM;

@ExtendWith(MockitoExtension.class)
class SharedAttributesHandlerTest {

    public static final String SESSION_ID = "the-session-id";
    public static final Map<String, Object> CREDENTIAL_INPUT_1 =
            Map.of(
                    "attributes",
                    Map.of(
                            "names",
                            Map.of("givenNames", List.of("John", "H"), "familyName", "Watson"),
                            "dateOfBirth",
                            "2021-03-01",
                            "address",
                            Map.of(
                                    "line1", "Current 123 Street",
                                    "postcode", "Current M34 1AA"),
                            "addressHistory",
                            List.of(
                                    Map.of(
                                            "line1", "Previous 123 Street",
                                            "postcode", "Previous M34 1AA"),
                                    Map.of(
                                            "line1", "Old 321 Street",
                                            "postcode", "Old M34 1AA"))));

    public static final Map<String, Object> CREDENTIAL_INPUT_2 =
            Map.of(
                    "attributes",
                    Map.of(
                            "names",
                            Map.of("givenNames", List.of("Sherlock"), "familyName", "Holmes"),
                            "dateOfBirth",
                            "1991-03-01",
                            "address",
                            Map.of(
                                    "line1", "321 Street",
                                    "postcode", "321 Street")));

    public static final Map<String, Object> CREDENTIAL_INPUT_3 =
            Map.of("attributes", Map.of("testProperty", "test value"));

    private static final String BASE64_PRIVATE_KEY =
            "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";

    private static final String BASE64_CERT =
            "MIIFVjCCAz4CCQDGbJ/u6uFT6DANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQGEwJHQjENMAsGA1UECAwEVGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEVEVzdDENMAsGA1UECwwEVEVzdDENMAsGA1UEAwwEVEVzdDETMBEGCSqGSIb3DQEJARYEVGVzdDAeFw0yMjAxMDcxNTM0NTlaFw0yMzAxMDcxNTM0NTlaMG0xCzAJBgNVBAYTAkdCMQ0wCwYDVQQIDARUZXN0MQ0wCwYDVQQHDARUZXN0MQ0wCwYDVQQKDARURXN0MQ0wCwYDVQQLDARURXN0MQ0wCwYDVQQDDARURXN0MRMwEQYJKoZIhvcNAQkBFgRUZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy1cVZ1KfFmgFlDQyf/R3LF/Js6jAS2Zzbs8WGSS0ys6Z+XR4x5DTIznZp5cHuuQmqOFylXSw5oGBwMXd2L6NimG9rJnJ4w8Gy5A6ImGsiDZC+3AXRBb5hq/IdDTBjbUqRxAKokSVwotWZt554BdSRPTmlYDujzxnClNKA06Xb/X3rTsgCUmZhUnSVtOzKytP3Bdv88VI5gq5tlZOtKXCB0PnJOqRbBmuL1RNkeTny4ZJW3I2ywSATwDDyDm4pJ8XGGNFKaYYTwr6uNTQ2VHb1FVC33oWbg+Zu9D4p5l7ONicCCF3V+GbvmyeCmHGnXznz0nYX1LFqaKtruEh3/GXyLy5X03Jzq6HhTf1SNFBmzziuCovhbR4v5aFDqAYNPWz+ajOdTUfP1I18c5jR1xGUxEiiLKBZWU1J5mhqCa+0CdI0mi3HwFmluudh47I2Xw++JiqZQpxRqNGcKJOPnWDgKOKXQ/ag37aJkxqoYWk9pQ/pXOdIKm//+B//8nWGo8BA/bfdmMHyzhWWxqtydjie2EZ5ODSdQ+yu1xU5cwP59BEQoU7FKVEGiJa4kzrsI2cgloUPlsPfLENMa5i09exDo//eDB/zNy9ACgGCriov1ex3uv4vHp3WtpZYe+akGEJeP0N5dejs0hkBuX+LUcM30TnQ424tEzcuaJ1F7r4FP0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAUh5gZx8S/XoZZoQai2uTyW/lyr1LpXMQyfvdWRr5+/OtFuASG3fAPXOTiUfuqH6Uma8BaXPRbSGWxBOFg0EbyvUY4UczZXZgVqyzkGjD2bVcnGra1OHz2AkcJm7OvzjMUvmXdDiQ8WcKIH16BZVsJFveTffJbM/KxL9UUdSLT0fNw1OvZWN1LxRj+X16B26ZnmaXPdmEC8MfwNcEU63qSlIbAvLg9Dp03weqO1qWR1vI/n1jwqidCUVwT0XF88/pJrds8/8guKlawhp9Yv+jMVYaawBiALR+5PFN56DivtmSVI5uv3oFh5tqJXXn9PhsPcIq0YKGQvvcdZl7vCikS65VzmswXBVFJNsYeeZ5NmiH2ANQd4+BLetgLAoXZxaOJ4nK+3Ml+gMwpZRRAbtixKJQDtVy+Ahuh1TEwTS1CERDYq43LhVYbMcgxdOLpZLvMew2tvJc3HfSWQKuF+NjGn/RwG54GyhjpdbfNZMB/EJXNJMt1j9RSVbPLsWjaENUkZoXE0otSou9tJOR0fwoqBJGUi5GCp98+iBdIQMAvXW5JkoDS6CM1FOfSv9ZXLvfXHOuBfKTDeVNy7u3QvyJ+BdkSc0iH4gj1F2zLHNIaZbDzwRzcDf2s3D1wTtoJ/WxfRSLGBMuUsXSduh9Md1S862N3Ce6wpri1IsgySCP84Y=";

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private KmsSigner mockKmsSigner;
    private SharedAttributesHandler underTest;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSASSASigner rsaSigner = new RSASSASigner(getPrivateKey());
        underTest = new SharedAttributesHandler(userIdentityService, rsaSigner);
    }

    @Test
    void shouldExtractSessionIdFromHeaderAndReturnSharedAttributesAndStatusOK()
            throws JsonProcessingException, ParseException, CertificateException, JOSEException {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        Map.of(
                                "CredentialIssuer1",
                                objectMapper.writeValueAsString(CREDENTIAL_INPUT_1),
                                "CredentialIssuer2",
                                objectMapper.writeValueAsString(CREDENTIAL_INPUT_2)));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        SignedJWT signedJWT = SignedJWT.parse(response.getBody());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        assertEquals(200, response.getStatusCode());
        assertEquals(1, claimsSet.get(CLAIMS_CLAIM).size());
        JsonNode claims = claimsSet.get(CLAIMS_CLAIM);
        assertEquals(4, claims.get(VC_HTTP_API_CLAIM).size());
        JsonNode vcAttributes = claims.get(VC_HTTP_API_CLAIM);

        assertEquals(2, (vcAttributes.get("names")).size());

        vcAttributes
                .get("names")
                .forEach(
                        (name) -> {
                            if (name.get("familyName").asText().equals("Holmes")) {
                                assertEquals(
                                        "[ \"Sherlock\" ]",
                                        name.get("givenNames").toPrettyString());
                            } else if (name.get("familyName").asText().equals("Watson")) {
                                assertEquals(
                                        "[ \"John\", \"H\" ]",
                                        name.get("givenNames").toPrettyString());
                            } else {
                                fail("Unexpected familyName");
                            }
                        });

        assertEquals("2021-03-01", vcAttributes.get("dateOfBirths").get(0).asText());
        assertTrue(vcAttributes.get("addresses").toPrettyString().contains("123 Street"));
        assertEquals(2, vcAttributes.get("addresses").size());
        assertEquals(2, vcAttributes.get("addressHistory").size());

        RSASSAVerifier rsaVerifier =
                new RSASSAVerifier((RSAPublicKey) getCertificate().getPublicKey());
        assertTrue(signedJWT.verify(rsaVerifier));
    }

    @Test
    void shouldReturnOKIfZeroCredentialExists() {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(Collections.emptyMap());

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnOKIfCredentialExistsWithoutAnySharedAttributeFields()
            throws JsonProcessingException, ParseException, JOSEException, CertificateException {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        Map.of(
                                "CredentialIssuer3",
                                objectMapper.writeValueAsString(CREDENTIAL_INPUT_3)));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        SignedJWT signedJWT = SignedJWT.parse(response.getBody());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        assertEquals(200, response.getStatusCode());
        assertEquals(1, claimsSet.get(CLAIMS_CLAIM).size());
        JsonNode claims = claimsSet.get(CLAIMS_CLAIM);
        assertEquals(4, claims.get(VC_HTTP_API_CLAIM).size());
        JsonNode vcAttributes = claims.get(VC_HTTP_API_CLAIM);
        assertEquals(0, vcAttributes.get("names").size());
        assertEquals(0, vcAttributes.get("dateOfBirths").size());
        assertEquals(0, vcAttributes.get("addresses").size());
        assertEquals(0, vcAttributes.get("addressHistory").size());

        RSASSAVerifier rsaVerifier =
                new RSASSAVerifier((RSAPublicKey) getCertificate().getPublicKey());
        assertTrue(signedJWT.verify(rsaVerifier));
    }

    @Test
    void shouldReturnBadRequestIfSessionIdIsNotInTheHeader() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("not-ipv-session-header", "dummy-value"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(400, response.getStatusCode());
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals(1010, responseBody.get("code"));
        assertEquals("Missing ipv session id header", responseBody.get("message"));
    }

    @Test
    void shouldReturn500WhenUnableToSignSharedAttributes() throws JsonProcessingException {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        Map.of(
                                "CredentialIssuer1",
                                objectMapper.writeValueAsString(CREDENTIAL_INPUT_1),
                                "CredentialIssuer2",
                                objectMapper.writeValueAsString(CREDENTIAL_INPUT_2)));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        SharedAttributesHandler handler =
                new SharedAttributesHandler(userIdentityService, mockKmsSigner);

        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);
        assertEquals(500, response.getStatusCode());
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals(
                ErrorResponse.FAILED_TO_SIGN_SHARED_ATTRIBUTES.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_SIGN_SHARED_ATTRIBUTES.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn500WhenUnableToMapToSharedAttribute() throws JsonProcessingException {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(Map.of("CredentialIssuer1", "{----"));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(500, response.getStatusCode());

        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals(
                ErrorResponse.FAILED_TO_GET_SHARED_ATTRIBUTES.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_GET_SHARED_ATTRIBUTES.getMessage(),
                responseBody.get("message"));
    }

    private Certificate getCertificate() throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(BASE64_CERT);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

    private RSAPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (RSAPrivateKey)
                KeyFactory.getInstance("RSA")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(BASE64_PRIVATE_KEY)));
    }
}
