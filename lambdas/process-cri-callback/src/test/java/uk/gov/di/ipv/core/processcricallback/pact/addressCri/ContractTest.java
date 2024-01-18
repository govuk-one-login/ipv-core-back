package uk.gov.di.ipv.core.processcricallback.pact.addressCri;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;
import uk.gov.di.ipv.core.processcricallback.pact.PactJwtIgnoreSignatureBodyBuilder;
import uk.gov.di.ipv.core.processcricallback.service.CriApiService;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "AddressCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
class ContractTest {
    private static final String TEST_USER = "test-subject";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static final String CRI_SIGNING_PRIVATE_KEY_JWK =
            """
            {"kty":"EC","d":"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}
            """;
    private static final String CRI_RSA_ENCRYPTION_PUBLIC_JWK =
            """
            {"kty":"RSA","e":"AQAB","n":"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q"}
            """;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    // We hardcode the VC headers and bodies like this so that it is easy to update them from JSON
    // sent by the CRI team
    private static final String VALID_VC_HEADER =
            """
            {
              "typ": "JWT",
              "alg": "ES256"
            }
            """;
    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_EXPERIAN_ADDRESS_VC_BODY =
            """
                {
                  "iss": "dummyAddressComponentId",
                  "sub": "test-subject",
                  "nbf": 4070908800,
                  "exp": 4070909400,
                  "vc": {
                     "type": [
                       "VerifiableCredential",
                       "IdentityCheckCredential"
                     ],
                     "credentialSubject": {
                       "name": [
                         {
                           "nameParts": [
                             {
                               "type": "GivenName",
                               "value": "Kenneth"
                             },
                             {
                               "type": "FamilyName",
                               "value": "Decerqueira"
                             }
                           ]
                         }
                       ],
                       "birthDate": [
                         {
                           "value": "1965-07-08"
                         }
                       ],
                       "address": [
                         {
                           "addressCountry": "GB",
                           "buildingName": "",
                           "streetName": "HADLEY ROAD",
                           "postalCode": "BA2 5AA",
                           "buildingNumber": "8",
                           "addressLocality": "BATH",
                           "validFrom": "2000-01-01"
                         }
                       ]
                     }
                   },
                   "jti": "dummyJti"
                 }
            """;

    private static final String VALID_ADDRESS_BODY =
            """
                {
                  "iss": "dummyAddressComponentId",
                  "sub": "test-subject",
                  "nbf": 4070908800,
                  "exp": 4070909400,
                  "vc": {
                     "type": [
                       "VerifiableCredential",
                       "IdentityCheckCredential"
                     ],
                     "credentialSubject": {
                       "name": [
                         {
                           "nameParts": [
                             {
                               "type": "GivenName",
                               "value": "Mary"
                             },
                             {
                               "type": "FamilyName",
                               "value": "Watson"
                             }
                           ]
                         }
                       ],
                       "birthDate": [
                         {
                           "value": "1932-02-25"
                         }
                       ],
                       "address": [
                         {
                            "buildingName": "221B",
                            "streetName": "BAKER STREET",
                            "postalCode": "NW1 6XE",
                            "addressLocality": "LONDON",
                            "validFrom": "1887-01-01"
                          }
                       ]
                     }
                   },
                   "jti": "dummyJti"
                 }
                    """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_EXPERIAN_SIGNATURE =
            "MY-0HSHHDSVZWFwzJrtCalS-jO8tFNwx1Oso6rbcfwQI69N7vRi_GEm4lQu-Da7Wn4bxkAMzxKM3R7PLu8yH_Q";
    private static final String VALID_VC_ADDRESS_SIGNATURE =
            "EFfq4iMeJ9ekCYJDZS8MTqxK0semEH7HRMac9Tc69zILtxzlVmJxnrhsVSgjpMNi3osCBUhWlz3Zh-jEUB4izw";
    public static final CriOAuthSessionItem CRI_O_AUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId", "dummyOAuthSessionId", "dummyCriId", "dummyConnection", 900);

    @Mock private ConfigService mockConfigService;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "AddressCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyAddressComponentId is the address CRI component ID")
                .given(
                        "Address CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Daddress&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlBZGRyZXNzQ29tcG9uZW50SWQiLCJleHAiOjQwNzA5MDk3MDAsImp0aSI6IlNjbkY0ZEdYdGhaWVhTXzVrODVPYkVvU1UwNFctSDNxYV9wNm5wdjJaVVkifQ.hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        (body) -> {
                                            body.stringType("access_token");
                                            body.stringValue("token_type", "Bearer");
                                            body.integerType("expires_in");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstAddressCri_retrievesAValidAccessToken(
            MockServer mockServer) throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // Signature generated by jwt.io by debugging the test and getting the client assertion JWT
        // generated by the test as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockSigner.sign(any(), any()))
                .thenReturn(
                        new Base64URL(
                                "hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw"));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate())
                .thenReturn("ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY");

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        BearerAccessToken accessToken =
                underTest.fetchAccessToken(
                        getCriCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        CRI_O_AUTH_SESSION_ITEM);
        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Pact(provider = "AddressCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeReturnsTokenError(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is an invalid api key")
                .given("dummyAddressComponentId is the address CRI component ID")
                .given(
                        "Address CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Daddress&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlBZGRyZXNzQ29tcG9uZW50SWQiLCJleHAiOjQwNzA5MDk3MDAsImp0aSI6IlNjbkY0ZEdYdGhaWVhTXzVrODVPYkVvU1UwNFctSDNxYV9wNm5wdjJaVVkifQ.hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(401)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAuthCodeReturnsTokenError")
    void fetchAccessToken_whenCalledAgainstAddressCri_throwsErrorWithInvalidAuthCode(
            MockServer mockServer) throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // Signature generated by jwt.io by debugging the test and getting the client assertion JWT
        // generated by the test as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockSigner.sign(any(), any()))
                .thenReturn(
                        new Base64URL(
                                "hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw"));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate())
                .thenReturn("ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY");

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> {
                            underTest.fetchAccessToken(
                                    getCriCallbackRequest(
                                            "dummyInvalidAuthCode", credentialIssuerConfig),
                                    CRI_O_AUTH_SESSION_ITEM);
                        });
        // Assert
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
    }

    @Pact(provider = "AddressCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsExperianIssuedCredential(
            PactDslWithProvider builder) throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyAddressComponentId is a valid issuer")
                .given("VC givenName is Kenneth")
                .given("VC familyName is Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("addressCountry is GB")
                .given("streetName is HADLEY ROAD")
                .given("buildingNumber is 8")
                .given("addressLocality is BATH")
                .given("validFrom is 2000-01-01")
                .uponReceiving("Valid POST request")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_EXPERIAN_ADDRESS_VC_BODY,
                                VALID_VC_EXPERIAN_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsExperianIssuedCredential")
    void testCallToDummyAddressIssueCredential(MockServer mockServer)
            throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, 4, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("A02", ciConfig1);
        ciConfigMap.put("A03", ciConfig2);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        getCriCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        CRI_O_AUTH_SESSION_ITEM);

        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("", addressNode.get("buildingName").asText());
                                assertEquals("HADLEY ROAD", addressNode.get("streetName").asText());
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());
                                assertEquals("BATH", addressNode.get("addressLocality").asText());
                                assertEquals("2000-01-01", addressNode.get("validFrom").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "AddressCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedAddressCredential(
            PactDslWithProvider builder) throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyAddressComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("buildingName is 221B")
                .given("streetName is BAKER STREET")
                .given("postalCode is NW1 6XE")
                .given("addressLocality is LONDON")
                .given("validFrom is 1887-01-01")
                .uponReceiving("Valid POST request")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_ADDRESS_BODY, VALID_VC_ADDRESS_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedAddressCredential")
    void testCallToDummyAddressIssuesCredential(MockServer mockServer)
            throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, 4, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("A02", ciConfig1);
        ciConfigMap.put("A03", ciConfig2);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        getCriCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        CRI_O_AUTH_SESSION_ITEM);

        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());

                                assertEquals("221B", addressNode.get("buildingName").asText());
                                assertEquals(
                                        "BAKER STREET", addressNode.get("streetName").asText());
                                assertEquals("NW1 6XE", addressNode.get("postalCode").asText());
                                assertEquals("LONDON", addressNode.get("addressLocality").asText());
                                assertEquals("1887-01-01", addressNode.get("validFrom").asText());

                                assertEquals("1932-02-25", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "AddressCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidCredentialsRequestThrowsError(PactDslWithProvider builder)
            throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is a valid access token")
                .uponReceiving("Invalid POST request")
                .path("/credential")
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Authorization",
                        "Bearer dummyInvalidAccessToken")
                .willRespondWith()
                .status(401)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidCredentialsRequestThrowsError")
    void testInvalidCredentialCallThrowsError(MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> {
                            underTest.fetchVerifiableCredential(
                                    new BearerAccessToken("dummyInvalidAccessToken"),
                                    getCriCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                                    CRI_O_AUTH_SESSION_ITEM);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, exception.getErrorResponse());
    }

    @NotNull
    private static CriCallbackRequest getCriCallbackRequest(
            String dummyAuthCode, OauthCriConfig credentialIssuerConfig) {
        return new CriCallbackRequest(
                dummyAuthCode,
                credentialIssuerConfig.getClientId(),
                "dummySessionId",
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=address",
                "dummyState",
                null,
                null,
                "dummyIpAddress",
                "dummyFeatureSet");
    }

    @NotNull
    private static OauthCriConfig getMockCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/token"))
                .credentialUrl(new URI("http://localhost:" + mockServer.getPort() + "/credential"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(CRI_SIGNING_PRIVATE_KEY_JWK)
                .encryptionKey(CRI_RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId("dummyAddressComponentId")
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=address"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
