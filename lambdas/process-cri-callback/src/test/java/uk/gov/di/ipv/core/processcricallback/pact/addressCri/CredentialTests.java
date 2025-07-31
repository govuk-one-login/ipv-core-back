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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "AddressCriVcProvider")
@MockServerConfig(hostInterface = "localhost")
class CredentialTests {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String MOCK_LOCK = "2025-07-28T10:14:07.494907165Z";
    private static final String MOCK_PROCESS_RESULT = "/journey/next";

    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "AddressCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsExperianIssuedCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyAddressComponentId is a valid issuer")
                .given("addressCountry is GB")
                .given("streetName is HADLEY ROAD")
                .given("buildingNumber is 8")
                .given("addressLocality is BATH")
                .given("validFrom is 2000-01-01")
                .uponReceiving("Valid credential request for Experian VC")
                .path("/credential/issue")
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
    void fetchVerifiableCredential_whenCalledAgainstAddressCri_retrievesAnExperianAddressVc(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialValidator(
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
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"), ADDRESS, CRI_OAUTH_SESSION_ITEM);

        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                ADDRESS,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("", addressNode.get("buildingName").asText());
                                assertEquals("HADLEY ROAD", addressNode.get("streetName").asText());
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());
                                assertEquals("BATH", addressNode.get("addressLocality").asText());
                                assertEquals("2000-01-01", addressNode.get("validFrom").asText());

                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "AddressCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedAddressCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyAddressComponentId is a valid issuer")
                .given("buildingName is 221B")
                .given("streetName is BAKER STREET")
                .given("postalCode is NW1 6XE")
                .given("addressLocality is LONDON")
                .given("validFrom is 1887-01-01")
                .uponReceiving("Valid credential request for old single address")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_VC_ADDRESS_BODY, VALID_VC_ADDRESS_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedAddressCredential")
    void fetchVerifiableCredential_whenCalledAgainstAddressCri_retrievesAnAddressVc(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialValidator(
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
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"), ADDRESS, CRI_OAUTH_SESSION_ITEM);

        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                ADDRESS,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                assertEquals("221B", addressNode.get("buildingName").asText());
                                assertEquals(
                                        "BAKER STREET", addressNode.get("streetName").asText());
                                assertEquals("NW1 6XE", addressNode.get("postalCode").asText());
                                assertEquals("LONDON", addressNode.get("addressLocality").asText());
                                assertEquals("1887-01-01", addressNode.get("validFrom").asText());

                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "AddressCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedInternationalAddressCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyAddressComponentId is a valid issuer")
                .given("addressCountry is CD")
                .given("addressRegion is North Kivu")
                .given("buildingName is Immeuble Commercial Plaza")
                .given("buildingNumber is 4")
                .given("subBuildingName is 3")
                .given("streetName is Boulevard Kanyamuhanga")
                .given("postalCode is 243")
                .given("addressLocality is Goma")
                .given("validFrom is 2020-01-01")
                .uponReceiving("Valid credential request for international address")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_VC_INTERNATIONAL_ADDRESS_BODY,
                                VALID_VC_INTERNATIONAL_ADDRESS_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedInternationalAddressCredential")
    void fetchVerifiableCredential_whenCalledAgainstAddressCri_retrievesAnInternationalAddressVc(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialValidator(
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
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"), ADDRESS, CRI_OAUTH_SESSION_ITEM);

        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                ADDRESS,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                // Just check the bits specific to international addresses
                                assertEquals(
                                        "North Kivu", addressNode.get("addressRegion").asText());
                                assertEquals("CD", addressNode.get("addressCountry").asText());

                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "AddressCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestForChangedAddressReturnsIssuedAddressCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyAddressComponentId is a valid issuer")
                .given("buildingName is 221B")
                .given("streetName is BAKER STREET")
                .given("postalCode is NW1 6XE")
                .given("addressLocality is LONDON")
                .given("validFrom is 1987-01-01")
                .given("second buildingName is 122")
                .given("second streetName is BURNS CRESCENT")
                .given("second postalCode is EH1 9GP")
                .given("second addressLocality is EDINBURGH")
                .given("second validFrom is 2017-01-01")
                .uponReceiving("Valid credential request for multiple addresses")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_VC_CHANGED_ADDRESS_BODY,
                                VALID_VC_CHANGED_ADDRESS_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestForChangedAddressReturnsIssuedAddressCredential")
    void
            fetchVerifiableCredential_whenCalledAgainstAddressCriForChangedAddress_retrievesAnAddressVc(
                    MockServer mockServer)
                    throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialValidator(
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
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"), ADDRESS, CRI_OAUTH_SESSION_ITEM);

        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                ADDRESS,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                assertEquals("221B", addressNode.get("buildingName").asText());
                                assertEquals(
                                        "BAKER STREET", addressNode.get("streetName").asText());
                                assertEquals("NW1 6XE", addressNode.get("postalCode").asText());
                                assertEquals("LONDON", addressNode.get("addressLocality").asText());
                                assertEquals("1987-01-01", addressNode.get("validFrom").asText());

                                JsonNode addressNode2 = credentialSubject.get("address").get(1);

                                assertEquals("122", addressNode2.get("buildingName").asText());
                                assertEquals(
                                        "BURNS CRESCENT", addressNode2.get("streetName").asText());
                                assertEquals("EH1 9GP", addressNode2.get("postalCode").asText());
                                assertEquals(
                                        "EDINBURGH", addressNode2.get("addressLocality").asText());
                                assertEquals("2017-01-01", addressNode2.get("validFrom").asText());

                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "AddressCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .uponReceiving("Invalid credential request")
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
            fetchVerifiableCredential_whenCalledAgainstAddressCriWithInvalidAccessToken_throwsAnException(
                    MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> {
                            underTest.fetchVerifiableCredential(
                                    new BearerAccessToken("dummyInvalidAccessToken"),
                                    ADDRESS,
                                    CRI_OAUTH_SESSION_ITEM);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, exception.getErrorResponse());
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
                .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=address"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyAddressComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId",
                    "dummyOAuthSessionId",
                    ADDRESS.getId(),
                    "dummyConnection",
                    MOCK_LOCK,
                    MOCK_PROCESS_RESULT,
                    900);

    // We hardcode the VC headers and bodies like this so that it is easy to update them from JSON
    // sent by the CRI team
    private static final String VALID_VC_HEADER =
            """
            {
              "typ": "JWT",
              "alg": "ES256",
              "kid": "did:web:dummyAddressComponentId#1753cf0b1e3647d91719820b74cf0c4f08782d0f072ebaf5ec4ee0873436a7ab"
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
                  "AddressCredential"
                ],
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
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
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_EXPERIAN_SIGNATURE =
            "Jy6iSQcjSYDsopf1AIPuscR_uwJTVdQaU3EcbFyZLukrFQ04fQWDFwUF2wzief2YL4v8_x2SVuMO7sqnn3m9MA"; // pragma: allowlist secret

    private static final String VALID_VC_ADDRESS_BODY =
            """
            {
              "iss": "dummyAddressComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "AddressCredential"
                ],
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
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
    private static final String VALID_VC_ADDRESS_SIGNATURE =
            "gHKt0bP-EDzMapHW5DfMJ93e31-WFltzYQxONTYlgN2okm5yRjkgjqsIyC1LFeeV6PtgctcW6FzrU_oqFS3GQA"; // pragma: allowlist secret

    private static final String VALID_VC_CHANGED_ADDRESS_BODY =
            """
            {
              "iss": "dummyAddressComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "AddressCredential"
                ],
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "buildingName": "221B",
                      "streetName": "BAKER STREET",
                      "postalCode": "NW1 6XE",
                      "addressLocality": "LONDON",
                      "validFrom": "1987-01-01"
                    },
                    {
                      "buildingName": "122",
                      "streetName": "BURNS CRESCENT",
                      "postalCode": "EH1 9GP",
                      "addressLocality": "EDINBURGH",
                      "validFrom": "2017-01-01"
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
    private static final String VALID_VC_CHANGED_ADDRESS_SIGNATURE =
            "2GkXxAwDnFVYbQMhsh3w-F4ffSlMVavviDIddMge_CjnQbWERBkhu-CCy6F9kGE1B8ZFrAlFAqDJQaT5PkbPbw"; // pragma: allowlist secret

    private static final String VALID_VC_INTERNATIONAL_ADDRESS_BODY =
            """
            {
              "iss": "dummyAddressComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "AddressCredential"
                ],
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "addressCountry": "CD",
                      "buildingName": "Immeuble Commercial Plaza",
                      "streetName": "Boulevard Kanyamuhanga",
                      "postalCode": "243",
                      "buildingNumber": "4",
                      "addressLocality": "Goma",
                      "validFrom": "2020-01-01",
                      "subBuildingName": "3",
                      "addressRegion": "North Kivu"
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
    private static final String VALID_VC_INTERNATIONAL_ADDRESS_SIGNATURE =
            "cr_bBHq1GD0dyl2L4ryF3fVD9-yLbS78wcRqFZaPB_FGAV9ANGjJHoRSGXoDNn0cib9tVeQDFYgeIZkm3iz46Q"; // pragma: allowlist secret
}
