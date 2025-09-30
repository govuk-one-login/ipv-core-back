package uk.gov.di.ipv.core.processcricallback.pact.experianKbvCri;

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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtIgnoreSignatureBodyBuilder;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_KBV;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "ExperianKbvCriVcProvider")
@MockServerConfig(hostInterface = "localhost")
class CredentialTests {
    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "ExperianKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC address uprn is 10022812929")
                .given("VC address organisationName is FINCH GROUP")
                .given("VC address buildingNumber is 16")
                .given("VC address buildingName is COY POND BUSINESS PARK")
                .given("VC address subBuildingName is UNIT 2B")
                .given("VC address dependentStreetName is KINGS PARK")
                .given("VC address streetName is BIG STREET")
                .given("VC address doubleDependentAddressLocality is SOME DISTRICT")
                .given("VC address dependentAddressLocality is LONG EATON")
                .given("VC address addressLocality is GREAT MISSENDEN")
                .given("VC address postalCode is HP16 0AL")
                .given("VC address addressCountry is GB")
                .given(
                        "VC evidence checkDetails are multiple_choice, multiple_choice, multiple_choice")
                .given("VC evidence checkDetails kbvQuality are 2, 2 and 1")
                .uponReceiving("Valid credential request for VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_VC_BODY, VALID_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstExperianKbvCri_retrievesAValidVc(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        EXPERIAN_KBV,
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_KBV,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode checkDetails =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("evidence")
                                                .get(0)
                                                .get("checkDetails");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("10022812929", addressNode.get("uprn").asText());
                                assertEquals(
                                        "FINCH GROUP",
                                        addressNode.get("organisationName").asText());
                                assertEquals(
                                        "UNIT 2B", addressNode.get("subBuildingName").asText());
                                assertEquals(
                                        "COY POND BUSINESS PARK",
                                        addressNode.get("buildingName").asText());
                                assertEquals("16", addressNode.get("buildingNumber").asText());
                                assertEquals(
                                        "KINGS PARK",
                                        addressNode.get("dependentStreetName").asText());
                                assertEquals("BIG STREET", addressNode.get("streetName").asText());
                                assertEquals(
                                        "SOME DISTRICT",
                                        addressNode.get("doubleDependentAddressLocality").asText());
                                assertEquals(
                                        "LONG EATON",
                                        addressNode.get("dependentAddressLocality").asText());
                                assertEquals(
                                        "GREAT MISSENDEN",
                                        addressNode.get("addressLocality").asText());
                                assertEquals("HP16 0AL", addressNode.get("postalCode").asText());
                                assertEquals("GB", addressNode.get("addressCountry").asText());

                                assertEquals(3, checkDetails.size());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "ExperianKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredentialWithFailedAnswer(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 0")
                .given("VC evidence txn is dummyTxn")
                .given("VC address uprn is 10022812929")
                .given("VC address organisationName is FINCH GROUP")
                .given("VC address buildingNumber is 16")
                .given("VC address subBuildingName is UNIT 2B")
                .given("VC address buildingName is COY POND BUSINESS PARK")
                .given("VC address dependentStreetName is KINGS PARK")
                .given("VC address streetName is BIG STREET")
                .given("VC address doubleDependentAddressLocality is SOME DISTRICT")
                .given("VC address dependentAddressLocality is LONG EATON")
                .given("VC address addressLocality is GREAT MISSENDEN")
                .given("VC address postalCode is HP16 0AL")
                .given("VC address addressCountry is GB")
                .uponReceiving("Valid credential request for VC with a Thin-file")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_THIN_FILE_VC_BODY,
                                VALID_THIN_FILE_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedCredentialWithFailedAnswer")
    void
            fetchVerifiableCredential_whenCalledAgainstExperianKbvCri_retrievesAValidVcWithFailedAnswer(
                    MockServer mockServer)
                    throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        EXPERIAN_KBV,
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_KBV,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("10022812929", addressNode.get("uprn").asText());
                                assertEquals(
                                        "FINCH GROUP",
                                        addressNode.get("organisationName").asText());
                                assertEquals(
                                        "UNIT 2B", addressNode.get("subBuildingName").asText());
                                assertEquals(
                                        "COY POND BUSINESS PARK",
                                        addressNode.get("buildingName").asText());
                                assertEquals("16", addressNode.get("buildingNumber").asText());
                                assertEquals(
                                        "KINGS PARK",
                                        addressNode.get("dependentStreetName").asText());
                                assertEquals("BIG STREET", addressNode.get("streetName").asText());
                                assertEquals(
                                        "SOME DISTRICT",
                                        addressNode.get("doubleDependentAddressLocality").asText());
                                assertEquals(
                                        "LONG EATON",
                                        addressNode.get("dependentAddressLocality").asText());
                                assertEquals(
                                        "GREAT MISSENDEN",
                                        addressNode.get("addressLocality").asText());
                                assertEquals("HP16 0AL", addressNode.get("postalCode").asText());
                                assertEquals("GB", addressNode.get("addressCountry").asText());

                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "ExperianKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .uponReceiving("Invalid credential request due to invalid access token")
                .path("/credential/issue")
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Authorization",
                        "Bearer dummyInvalidAccessToken")
                .willRespondWith()
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAccessTokenReturns403")
    void
            fetchVerifiableCredential_whenCalledAgainstExperianKbvCriWithInvalidAuthCode_throwsAnException(
                    MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchVerifiableCredential(
                                        new BearerAccessToken("dummyInvalidAccessToken"),
                                        EXPERIAN_KBV,
                                        getCriOAuthSessionItem()));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @Pact(provider = "ExperianKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredentialWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 0")
                .given("VC evidence txn is dummyTxn")
                .given("VC address uprn is 10022812929")
                .given("VC address organisationName is FINCH GROUP")
                .given("VC address buildingNumber is 16")
                .given("VC address subBuildingName is UNIT 2B")
                .given("VC address buildingName is COY POND BUSINESS PARK")
                .given("VC address dependentStreetName is KINGS PARK")
                .given("VC address streetName is BIG STREET")
                .given("VC address doubleDependentAddressLocality is SOME DISTRICT")
                .given("VC address dependentAddressLocality is LONG EATON")
                .given("VC address addressLocality is GREAT MISSENDEN")
                .given("VC address postalCode is HP16 0AL")
                .given("VC address addressCountry is GB")
                .given("VC evidence checkDetails are multiple_choice")
                .given("VC evidence checkDetails kbvQuality are 3")
                .given(
                        "VC evidence failedCheckDetails are multiple_choice, multiple_choice, multiple_choice")
                .given("VC ci is V03")
                .uponReceiving("Valid credential request for VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_VC_BODY, FAILED_VC_SIGNATURE))
                .status(200)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedCredentialWithCi")
    void fetchVerifiableCredential_whenCalledAgainstExperianKbvCri_retrievesAValidVcWithACi(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        EXPERIAN_KBV,
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_KBV,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");

                                JsonNode vcClaim =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode evidence = vcClaim.get("evidence").get(0);
                                JsonNode ciNode = evidence.get("ci");
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                JsonNode failedCheckDetailsNode =
                                        evidence.get("failedCheckDetails");

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("10022812929", addressNode.get("uprn").asText());
                                assertEquals(
                                        "FINCH GROUP",
                                        addressNode.get("organisationName").asText());
                                assertEquals(
                                        "UNIT 2B", addressNode.get("subBuildingName").asText());
                                assertEquals(
                                        "COY POND BUSINESS PARK",
                                        addressNode.get("buildingName").asText());
                                assertEquals("16", addressNode.get("buildingNumber").asText());
                                assertEquals(
                                        "KINGS PARK",
                                        addressNode.get("dependentStreetName").asText());
                                assertEquals("BIG STREET", addressNode.get("streetName").asText());
                                assertEquals(
                                        "SOME DISTRICT",
                                        addressNode.get("doubleDependentAddressLocality").asText());
                                assertEquals(
                                        "LONG EATON",
                                        addressNode.get("dependentAddressLocality").asText());
                                assertEquals(
                                        "GREAT MISSENDEN",
                                        addressNode.get("addressLocality").asText());
                                assertEquals("HP16 0AL", addressNode.get("postalCode").asText());
                                assertEquals("GB", addressNode.get("addressCountry").asText());

                                assertEquals("V03", ciNode.get(0).asText());

                                assertEquals(
                                        "multiple_choice",
                                        failedCheckDetailsNode
                                                .get(0)
                                                .get("kbvResponseMode")
                                                .asText());
                                assertEquals(
                                        "multiple_choice",
                                        failedCheckDetailsNode
                                                .get(1)
                                                .get("kbvResponseMode")
                                                .asText());
                                assertEquals(
                                        "kbv",
                                        failedCheckDetailsNode.get(0).get("checkMethod").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    private void configureMockConfigService(OauthCriConfig credentialIssuerConfig) {
        ContraIndicatorConfig ciConfig = new ContraIndicatorConfig(null, 4, null, null);
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("V03", ciConfig);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);
        // This mock doesn't get reached in error cases, but it would be messy to explicitly not set
        // it
        Mockito.lenient()
                .when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(ciConfigMap);
    }

    @NotNull
    private VerifiableCredentialValidator getVerifiableCredentialValidator() {
        return new VerifiableCredentialValidator(
                mockConfigService,
                ((exactMatchClaims, requiredClaims) ->
                        new FixedTimeJWTClaimsVerifier<>(
                                exactMatchClaims,
                                requiredClaims,
                                Date.from(CURRENT_TIME.instant()))));
    }

    @NotNull
    private static CriOAuthSessionItem getCriOAuthSessionItem() {
        return new CriOAuthSessionItem(
                "dummySessionId",
                "dummyOAuthSessionId",
                EXPERIAN_KBV.getId(),
                "dummyConnection",
                900);
    }

    @NotNull
    private static OauthCriConfig getMockCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/token"))
                .credentialUrl(
                        new URI("http://localhost:" + mockServer.getPort() + "/credential/issue"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(EC_PRIVATE_KEY_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=kbv"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyExperianKbvComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    // We hardcode the VC headers and bodies like this so that it is easy to update them from JSON
    // sent by the CRI team
    private static final String VALID_VC_HEADER =
            """
            {
              "typ": "JWT",
              "alg": "ES256",
              "kid": "did:web:dummyExperianKbvComponentId#5187377245dfa768c91884dba9eea7e7dbbd1ceec1ddb4b14b658c0c42b04432"
            }
            """;

    private static final String VALID_VC_BODY =
            """
            {
               "iss": "dummyExperianKbvComponentId",
               "sub": "test-subject",
               "nbf": 4070908800,
               "exp": 4070909400,
               "vc": {
                 "@context": [
                   "https://www.w3.org/2018/credentials/v1",
                   "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                 ],
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
                   "address": [
                     {
                       "addressCountry": "GB",
                       "uprn": 10022812929,
                       "buildingName": "COY POND BUSINESS PARK",
                       "subBuildingName": "UNIT 2B",
                       "organisationName": "FINCH GROUP",
                       "streetName": "BIG STREET",
                       "dependentStreetName": "KINGS PARK",
                       "postalCode": "HP16 0AL",
                       "buildingNumber": "16",
                       "dependentAddressLocality": "LONG EATON",
                       "addressLocality": "GREAT MISSENDEN",
                       "doubleDependentAddressLocality": "SOME DISTRICT"
                     }
                   ],
                   "birthDate": [
                     {
                       "value": "1932-02-25"
                     }
                   ]
                 },
                 "evidence": [
                   {
                     "txn": "dummyTxn",
                     "verificationScore": 2,
                     "checkDetails": [
                       {
                         "checkMethod": "kbv",
                         "kbvResponseMode": "multiple_choice",
                         "kbvQuality": 2
                       },
                       {
                         "checkMethod": "kbv",
                         "kbvResponseMode": "multiple_choice",
                         "kbvQuality": 2
                       },
                       {
                         "checkMethod": "kbv",
                         "kbvResponseMode": "multiple_choice",
                         "kbvQuality": 1
                       }
                     ],
                     "type": "IdentityCheck"
                   }
                 ]
               },
               "jti": "dummyJti"
            }
            """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_SIGNATURE =
            "cHYsPI1M8wa6JOwU70yVZv8E7Bb6ev1QV20Nomm6e3QPKzyKo2rxuy8Gsk3r9fErXy8hv1N0L-LuZn7pLTSQSQ"; // pragma: allowlist secret

    private static final String VALID_THIN_FILE_VC_BODY =
            """
            {
              "iss": "dummyExperianKbvComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
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
                  "address": [
                    {
                      "addressCountry": "GB",
                      "uprn": 10022812929,
                      "buildingName": "COY POND BUSINESS PARK",
                      "subBuildingName": "UNIT 2B",
                      "organisationName": "FINCH GROUP",
                      "streetName": "BIG STREET",
                      "dependentStreetName": "KINGS PARK",
                      "postalCode": "HP16 0AL",
                      "buildingNumber": "16",
                      "dependentAddressLocality": "LONG EATON",
                      "addressLocality": "GREAT MISSENDEN",
                      "doubleDependentAddressLocality": "SOME DISTRICT"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1932-02-25"
                    }
                  ]
                },
                "evidence": [
                  {
                    "txn": "dummyTxn",
                    "verificationScore": 0,
                    "type": "IdentityCheck"
                  }
                ]
              },
              "jti": "dummyJti"
            }
            """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_THIN_FILE_VC_SIGNATURE =
            "gjiDQ5rzrzFjrVqvOE2ayqnbaQlDQpa7VHRBh-cGhar5Ty4pEkcTYr6LLChT5NoGPkSE9PlT9G4SuSEkako6gw"; // pragma: allowlist secret

    private static final String FAILED_VC_BODY =
            """
            {
              "iss": "dummyExperianKbvComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
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
                  "address": [
                    {
                      "addressCountry": "GB",
                      "uprn": 10022812929,
                      "buildingName": "COY POND BUSINESS PARK",
                      "subBuildingName": "UNIT 2B",
                      "organisationName": "FINCH GROUP",
                      "streetName": "BIG STREET",
                      "dependentStreetName": "KINGS PARK",
                      "postalCode": "HP16 0AL",
                      "buildingNumber": "16",
                      "dependentAddressLocality": "LONG EATON",
                      "addressLocality": "GREAT MISSENDEN",
                      "doubleDependentAddressLocality": "SOME DISTRICT"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1932-02-25"
                    }
                  ]
                },
                "evidence": [
                  {
                    "txn": "dummyTxn",
                    "verificationScore": 0,
                    "ci": [
                      "V03"
                    ],
                    "checkDetails": [
                      {
                        "checkMethod": "kbv",
                        "kbvResponseMode": "multiple_choice",
                        "kbvQuality": 3
                      }
                    ],
                    "failedCheckDetails": [
                      {
                        "checkMethod": "kbv",
                        "kbvResponseMode": "multiple_choice"
                      },
                      {
                        "checkMethod": "kbv",
                        "kbvResponseMode": "multiple_choice"
                      },
                      {
                        "checkMethod": "kbv",
                        "kbvResponseMode": "multiple_choice"
                      }
                    ],
                    "type": "IdentityCheck"
                  }
                ]
              },
              "jti": "dummyJti"
            }
            """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_VC_SIGNATURE =
            "m3xuM0mpZ3lTHhDk9hOLa79hyLr1x9fcCavK7RCD_OOGo04QvZFyxtV6OoUPnANU-WxEr3iMv7ZNBLPEcQb90g"; // pragma: allowlist secret
}
