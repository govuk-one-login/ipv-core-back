package uk.gov.di.ipv.core.processcricallback.pact.drivingLicenceCri;

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
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "DrivingLicenceVcProvider")
@MockServerConfig(hostInterface = "localhost")
class CredentialTests {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String MOCK_LOCK = "2025-07-28T10:14:07.494907165Z";
    private static final String MOCK_PROCESS_RESULT = "/journey/next";

    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "DrivingLicenceVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvlaIssuedCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC evidence validityScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issueNumber is 12")
                .given("VC driving licence issuedBy is DVLA")
                .given("VC driving licence personalNumber is PARKE610112PBFGH")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVLA VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_DVLA_VC_BODY, VALID_DVLA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvlaIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesAValidDvlaVc(
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
                        DRIVING_LICENCE,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                DRIVING_LICENCE,
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
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "PARKE610112PBFGH",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVLA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvlaResponseWithCi(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC has a CI of D02")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issueNumber is 12")
                .given("VC driving licence issuedBy is DVLA")
                .given("VC driving licence personalNumber is PARKE610112PBFGH")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVLA VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_DVLA_VC_BODY, FAILED_DVLA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvlaResponseWithCi")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesADvlaVcWithACi(
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
                        DRIVING_LICENCE,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                DRIVING_LICENCE,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vcClaim.get("credentialSubject");
                                JsonNode evidence = vcClaim.get("evidence").get(0);

                                JsonNode ciNode = evidence.get("ci");
                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("D02", ciNode.get(0).asText());

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "PARKE610112PBFGH",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVLA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvaIssuedCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC evidence validityScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issuedBy is DVA")
                .given("VC driving licence personalNumber is 55667788")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVA VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_DVA_VC_BODY, VALID_DVA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvaIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesAValidDvaVc(
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
                        DRIVING_LICENCE,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                DRIVING_LICENCE,
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
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "55667788",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvaResponseWithCi(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC has a CI of D02")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issueNumber is 12")
                .given("VC driving licence issuedBy is DVA")
                .given("VC driving licence personalNumber is 55667780")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVA VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_DVA_VC_BODY, FAILED_DVA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvaResponseWithCi")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesADvaVcWithACi(
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
                        DRIVING_LICENCE,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                DRIVING_LICENCE,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vcClaim.get("credentialSubject");
                                JsonNode evidence = vcClaim.get("evidence").get(0);

                                JsonNode ciNode = evidence.get("ci");
                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("D02", ciNode.get(0).asText());

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "55667780",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
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
            fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCriWithInvalidAuthCode_throwsAnException(
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
                                        DRIVING_LICENCE,
                                        CRI_OAUTH_SESSION_ITEM));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @NotNull
    private VerifiableCredentialValidator getVerifiableCredentialJwtValidator() {
        return new VerifiableCredentialValidator(
                mockConfigService,
                ((exactMatchClaims, requiredClaims) ->
                        new FixedTimeJWTClaimsVerifier<>(
                                exactMatchClaims,
                                requiredClaims,
                                Date.from(CURRENT_TIME.instant()))));
    }

    private void configureMockConfigService(OauthCriConfig credentialIssuerConfig) {
        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("D02", ciConfig1);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);
        // This mock doesn't get reached in error cases, but it would be messy to explicitly not set
        // it
        Mockito.lenient()
                .when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(ciConfigMap);
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
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=drivingLicence"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyDrivingLicenceComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId",
                    "dummyOAuthSessionId",
                    DRIVING_LICENCE.getId(),
                    "dummyConnection",
                    MOCK_LOCK,
                    MOCK_PROCESS_RESULT,
                    900);

    // We hardcode the VC headers and bodies like this so that it is easy to update them from JSON
    // sent by the CRI team
    private static final String VALID_VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;
    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_DVLA_VC_BODY =
            """
            {
              "iss": "dummyDrivingLicenceComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "postalCode": "BS981TL",
                      "addressCountry": "GB"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "PARKE610112PBFGH",
                      "expiryDate": "2062-12-09",
                      "issueNumber": "12",
                      "issuedBy": "DVLA",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "dummyTxn",
                    "activityHistoryScore": 1,
                    "strengthScore": 3,
                    "validityScore": 2,
                    "checkDetails": [
                      {
                        "checkMethod": "data",
                        "identityCheckPolicy": "published",
                        "activityFrom": "1982-05-23"
                      }
                    ]
                  }
                ]
              },
              "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_DVLA_VC_SIGNATURE =
            "sCeBi6_FUnX3XGFxvAaqXoI6BKSHfBrOa4y-4j5iQ_--JJ4A4_PRbgnPNAFtR6-IN-JD7gxhcY-4yDN38W856Q"; // pragma: allowlist secret

    private static final String FAILED_DVLA_VC_BODY =
            """
            {
              "iss": "dummyDrivingLicenceComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "postalCode": "BS981TL",
                      "addressCountry": "GB"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "PARKE610112PBFGH",
                      "expiryDate": "2062-12-09",
                      "issueNumber": "12",
                      "issuedBy": "DVLA",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "dummyTxn",
                    "activityHistoryScore": 0,
                    "strengthScore": 3,
                    "validityScore": 0,
                    "ci": [
                      "D02"
                    ],
                    "failedCheckDetails": [
                      {
                        "checkMethod": "data",
                        "identityCheckPolicy": "published",
                        "activityFrom": "1982-05-23"
                      }
                    ]
                  }
                ]
              },
              "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_DVLA_VC_SIGNATURE =
            "4l-CAl_X8XvPJku1zv_JnXfnTfow1KKeQsa7AUIVSe1pUdIlyugoIybrJp5SMu7Sxp1R02ACUkH361m1FSQwkg"; // pragma: allowlist secret

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_DVA_VC_BODY =
            """
            {
              "iss": "dummyDrivingLicenceComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "postalCode": "BS981TL",
                      "addressCountry": "GB"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "55667788",
                      "expiryDate": "2062-12-09",
                      "issuedBy": "DVA",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "dummyTxn",
                    "activityHistoryScore": 1,
                    "strengthScore": 3,
                    "validityScore": 2,
                    "checkDetails": [
                      {
                        "checkMethod": "data",
                        "identityCheckPolicy": "published",
                        "activityFrom": "1982-05-23"
                      }
                    ]
                  }
                ]
              },
              "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_DVA_VC_SIGNATURE =
            "3PckWPMtOyJ5YttPZlWZw0xXTUNuD4ogIyIzQiTmUuBZqaH_OOU6tvPDJXVtU9PvfDr8C3YDEhDOWnFFTG6P6g"; // pragma: allowlist secret

    private static final String FAILED_DVA_VC_BODY =
            """
            {
              "iss": "dummyDrivingLicenceComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "postalCode": "BS981TL",
                      "addressCountry": "GB"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "55667780",
                      "expiryDate": "2062-12-09",
                      "issuedBy": "DVA",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "dummyTxn",
                    "activityHistoryScore": 0,
                    "strengthScore": 3,
                    "validityScore": 0,
                            "ci": [
                      "D02"
                    ],
                    "failedCheckDetails": [
                      {
                        "checkMethod": "data",
                        "identityCheckPolicy": "published",
                        "activityFrom": "1982-05-23"
                      }
                    ]
                  }
                ]
              },
              "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_DVA_VC_SIGNATURE =
            "hTrCCVEc7eFZX2wniTw1pu1Pzi07cRysXV5PHxUo87K8b3EDR7a756t5ipjFY9hmNf1xo-6Tdd3UerXkVPmOnw"; // pragma: allowlist secret
}
