package uk.gov.di.ipv.core.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.helpers.KmsEs256Signer;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_WITHOUT_SHARED_ATTRIBUTES;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.vcClaim;
import static uk.gov.di.ipv.core.sharedattributes.SharedAttributesHandler.SHARED_CLAIMS;

@ExtendWith(MockitoExtension.class)
class SharedAttributesHandlerTest {

    public static final String SESSION_ID = "the-session-id";

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private KmsEs256Signer mockKmsSigner;
    private SharedAttributesHandler underTest;

    @BeforeEach
    void setUp() throws Exception {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());
        underTest = new SharedAttributesHandler(userIdentityService, signer);
    }

    @Test
    void shouldExtractSessionIdFromHeaderAndReturnSharedAttributesAndStatusOK() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        new UserIdentity(
                                List.of(
                                        generateVerifiableCredential(
                                                vcClaim(CREDENTIAL_ATTRIBUTES_1)),
                                        generateVerifiableCredential(
                                                vcClaim(CREDENTIAL_ATTRIBUTES_2)))));

        List<Address> addressList = new ArrayList<>();

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        SignedJWT signedJWT = SignedJWT.parse(response.getBody());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        assertEquals(200, response.getStatusCode());
        assertEquals(3, claimsSet.get(SHARED_CLAIMS).size());
        JsonNode vcAttributes = claimsSet.get(SHARED_CLAIMS);

        JsonNode address = vcAttributes.get("address");
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
        assertEquals(3, (vcAttributes.get("birthDate")).size());

        ECDSAVerifier verifier = new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK));
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    void shouldReturnOKIfZeroCredentialExists() {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(new UserIdentity(Collections.emptyList()));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnOKIfCredentialExistsWithoutAnySharedAttributeFields() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        new UserIdentity(
                                List.of(
                                        generateVerifiableCredential(
                                                vcClaim(
                                                        CREDENTIAL_ATTRIBUTES_WITHOUT_SHARED_ATTRIBUTES)))));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        SignedJWT signedJWT = SignedJWT.parse(response.getBody());
        JsonNode claimsSet = objectMapper.readTree(signedJWT.getJWTClaimsSet().toString());

        assertEquals(200, response.getStatusCode());
        assertEquals(3, claimsSet.get(SHARED_CLAIMS).size());
        JsonNode vcAttributes = claimsSet.get(SHARED_CLAIMS);
        assertEquals(1, vcAttributes.get("name").size());
        assertEquals(0, vcAttributes.get("birthDate").size());
        assertEquals(0, vcAttributes.get("address").size());

        ECDSAVerifier verifier = new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK));
        assertTrue(signedJWT.verify(verifier));
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
    void shouldReturn500WhenUnableToSignSharedAttributes() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        new UserIdentity(
                                List.of(
                                        generateVerifiableCredential(
                                                vcClaim(CREDENTIAL_ATTRIBUTES_1)),
                                        generateVerifiableCredential(
                                                vcClaim(CREDENTIAL_ATTRIBUTES_2)))));

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
    void shouldReturn500WhenUnableToParseCredentials() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(new UserIdentity(List.of("Not a verifiable credential")));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(500, response.getStatusCode());

        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn500IfCredentialSubjectMissingFromIssuedCredential() throws Exception {
        Map<String, Object> vcClaim = vcClaim(Map.of());
        vcClaim.remove(VC_CREDENTIAL_SUBJECT);

        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(new UserIdentity(List.of(generateVerifiableCredential(vcClaim))));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(500, response.getStatusCode());

        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals(ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getMessage(), responseBody.get("message"));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
