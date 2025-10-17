package uk.gov.di.ipv.core.library.sis.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslJsonRootValue;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.fixtures.VcFixtures;
import uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.client.SisClient;
import uk.gov.di.ipv.core.library.sis.client.SisGetStoredIdentityResult;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityCheckDto;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityContent;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtBuilder;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static io.netty.handler.codec.http.HttpMethod.POST;
import static org.apache.hc.core5.http.ContentType.APPLICATION_JSON;
import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static org.apache.hc.core5.http.HttpStatus.SC_BAD_REQUEST;
import static org.apache.hc.core5.http.HttpStatus.SC_FORBIDDEN;
import static org.apache.hc.core5.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static org.apache.hc.core5.http.HttpStatus.SC_NOT_FOUND;
import static org.apache.hc.core5.http.HttpStatus.SC_OK;
import static org.apache.hc.core5.http.HttpStatus.SC_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.kennethDecerqueiraName;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "StoredIdentityServiceProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {

    private static final String X_API_KEY_HEADER = "x-api-key";
    private static final String SIS_API_KEY = "some-api-key"; // pragma: allowlist secret
    private static final String TEST_SIS_ACCESS_TOKEN = "test-access-token";
    private static final String TEST_INVALID_SIS_ACCESS_TOKEN = "test-invalid-access-token";
    private static final String TEST_EXPIRED_SIS_ACCESS_TOKEN = "test-expired-access-token";
    private static final List<Vot> TEST_VOTS = List.of(Vot.P1, Vot.P2);
    private static final String TEST_JOURNEY_ID = "test-gov-journey-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_VTM = "some-vtm";

    private static final String USER_IDENTITY_ENDPOINT_PATH = "/user-identity";

    private static final List<String> VC_SIGNATURES =
            List.of(
                    "N7PxhfkFkmyTQFKyAXMyS_H6NuF-wDzEktb_dVurulSRMMXhnxhbR2rxs9Tc-KQB0iXb1_9aBI8XCy2AbGQvFQ", // pragma: allowlist secret
                    "S4NJPciimbfx08js9m98hsrKL4bJHtBQyKGtrdIzIfYmBPjrU9paz_u_1hCrHZ8ijyQo5RPmQlMP-_c5euvZHw", // pragma: allowlist secret
                    "A9OHuKI8N5h4C457Q4qtNvkSFKfFeVM4sEGwqRPcSHiQylzhxRyq00e1DUQLmSdie9XIk0CfiQSA_r7-mmCbAw", // pragma: allowlist secret
                    "y44v0pEA88zuDhDFDCDcPgn96p9bSFojxvPA1BxGXNxD0nPzQN6MRhmOYpSQx8Mov_3KYAxnfyiwRzeArXJkqA"); // pragma: allowlist secret

    private static final IdentityClaim IDENTITY_CLAIM =
            new IdentityClaim(
                    List.of(kennethDecerqueiraName()),
                    List.of(BirthDateGenerator.createBirthDate("1965-07-08")));
    private static final SisStoredIdentityContent SIS_CONTENT =
            new SisStoredIdentityContent(
                    TEST_USER_ID,
                    Vot.P2,
                    TEST_VTM,
                    VC_SIGNATURES,
                    List.of(VcFixtures.vcDcmawPassport().getVcString()),
                    IDENTITY_CLAIM,
                    null,
                    VcFixtures.passportDetails(),
                    null,
                    null);

    private static final SisGetStoredIdentityResult EXPECTED_INVALID_RESULT =
            new SisGetStoredIdentityResult(false, false, null);

    private static final Vot EXPECTED_VOT = Vot.P2;

    @Mock private ConfigService mockConfigService;
    private SisClient sisClient;

    @BeforeEach
    void setup(MockServer mockServer) {
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockConfigService.getSisApplicationUrl())
                .thenReturn(URI.create("http://localhost:" + mockServer.getPort()));
        sisClient = new SisClient(mockConfigService);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetStoredIdentityRequestReturns200(
            PactDslWithProvider builder) {
        return builder.given(String.format("%s and %s are valid", TEST_VOTS, TEST_JOURNEY_ID))
                .given(String.format("A request returns at least %s vot", EXPECTED_VOT))
                .uponReceiving("A request to get user stored identity")
                .path(USER_IDENTITY_ENDPOINT_PATH)
                .method(POST.name())
                .headers(
                        Map.of(
                                AUTHORIZATION,
                                String.format("Bearer %s", TEST_SIS_ACCESS_TOKEN),
                                CONTENT_TYPE,
                                APPLICATION_JSON.getMimeType(),
                                X_API_KEY_HEADER,
                                SIS_API_KEY))
                .body(getValidRequestBody())
                .willRespondWith()
                .status(SC_OK)
                .body(getValidResponseBody())
                .toPact();
    }

    @Test
    @DisplayName("POST /user-identity - 200 returns stored identity")
    @PactTestFor(pactMethod = "validGetStoredIdentityRequestReturns200")
    void testGetUserIdentityRequestReturns200(MockServer mockServer) {
        // Arrange
        var expectedIdentityDetails =
                new SisStoredIdentityCheckDto(SIS_CONTENT, true, false, Vot.P2, true, true);
        var expectedValidResult =
                new SisGetStoredIdentityResult(true, true, expectedIdentityDetails);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(
                expectedValidResult.requestSucceeded(),
                sisGetStoredIdentityResult.requestSucceeded());
        assertEquals(
                expectedValidResult.identityWasFound(),
                sisGetStoredIdentityResult.identityWasFound());

        var realIdentityDetails = sisGetStoredIdentityResult.identityDetails();
        assertEquals(
                expectedIdentityDetails.content().getVot(), realIdentityDetails.content().getVot());
        assertEquals(
                expectedIdentityDetails.content().getCredentialSignatures(),
                realIdentityDetails.content().getCredentialSignatures());
        assertEquals(expectedIdentityDetails.vot(), realIdentityDetails.vot());
        assertEquals(expectedIdentityDetails.isValid(), realIdentityDetails.isValid());
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidApiKeyReturns403(PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                String.format("%s is not a valid api-key", SIS_API_KEY),
                SC_FORBIDDEN,
                TEST_SIS_ACCESS_TOKEN,
                builder);
    }

    @Test
    @DisplayName("POST /user-identity - 403 due to invalid api key")
    @PactTestFor(pactMethod = "invalidApiKeyReturns403")
    void testGetUserIdentityRequestReturns403DueToInvalidApiKey(MockServer mockServer) {
        // Arrange
        var expectedFailedResult = new SisGetStoredIdentityResult(false, false, null);

        // Act/Assert
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(expectedFailedResult, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns404(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                String.format(
                        "%s and %s are valid but record was not found", TEST_VOTS, TEST_JOURNEY_ID),
                SC_NOT_FOUND,
                TEST_SIS_ACCESS_TOKEN,
                builder);
    }

    @Test
    @DisplayName("POST /user-identity - 404 returns empty with successful request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns404")
    void testGetUserIdentityRequestReturns404(MockServer mockServer) {
        // Arrange
        var expectedNotFoundResult = new SisGetStoredIdentityResult(true, false, null);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(expectedNotFoundResult, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns401(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                String.format("%s is invalid bearer token", TEST_INVALID_SIS_ACCESS_TOKEN),
                SC_UNAUTHORIZED,
                TEST_INVALID_SIS_ACCESS_TOKEN,
                builder);
    }

    @Test
    @DisplayName("POST /user-identity - 401 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns401")
    void testGetUserIdentityRequestReturns401(MockServer mockServer) {
        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(
                        TEST_INVALID_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns403(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                String.format("%s is expired bearer token", TEST_EXPIRED_SIS_ACCESS_TOKEN),
                SC_FORBIDDEN,
                TEST_EXPIRED_SIS_ACCESS_TOKEN,
                builder);
    }

    @Test
    @DisplayName("POST /user-identity - 403 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns403")
    void testGetUserIdentityRequestReturns403(MockServer mockServer) {
        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(
                        TEST_EXPIRED_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns500(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                "A request returns 500", SC_INTERNAL_SERVER_ERROR, TEST_SIS_ACCESS_TOKEN, builder);
    }

    @Test
    @DisplayName("POST /user-identity - 500 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns500")
    void testGetUserIdentityRequestReturns500(MockServer mockServer) {
        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns400(
            PactDslWithProvider builder) {
        return builder.given("Request is missing mandatory field vtr")
                .uponReceiving("A request to get user stored identity")
                .path(USER_IDENTITY_ENDPOINT_PATH)
                .method(POST.name())
                .headers(
                        Map.of(
                                AUTHORIZATION,
                                String.format("Bearer %s", TEST_SIS_ACCESS_TOKEN),
                                CONTENT_TYPE,
                                APPLICATION_JSON.getMimeType()))
                .body(
                        newJsonBody(
                                        body ->
                                                // missing vtr
                                                body.stringValue(
                                                        "govukSigninJourneyId", TEST_JOURNEY_ID))
                                .build())
                .willRespondWith()
                .status(SC_BAD_REQUEST)
                .toPact();
    }

    @Test
    @DisplayName("POST /user-identity - 400 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns400")
    void testGetUserIdentityRequestReturns400(MockServer mockServer) {
        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, null, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturnsMalformed200(
            PactDslWithProvider builder) {
        return builder.given("Malformed response is missing vtr")
                .uponReceiving("A request to get user stored identity")
                .path(USER_IDENTITY_ENDPOINT_PATH)
                .method(POST.name())
                .headers(
                        Map.of(
                                AUTHORIZATION,
                                String.format("Bearer %s", TEST_SIS_ACCESS_TOKEN),
                                CONTENT_TYPE,
                                APPLICATION_JSON.getMimeType()))
                .body(getValidRequestBody())
                .willRespondWith()
                .status(SC_OK)
                .body(getMalformedResponse())
                .toPact();
    }

    @SuppressWarnings("java:S4144")
    @Test
    @DisplayName("POST /user-identity - malformed 200 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturnsMalformed200")
    void testGetUserIdentityRequestReturnsMalformed200(MockServer mockServer) {
        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    private static RequestResponsePact buildStoredIdentityInteraction(
            String given, int httpStatusCode, String bearerToken, PactDslWithProvider builder) {
        return builder.given(given)
                .uponReceiving("A request to get user stored identity")
                .path(USER_IDENTITY_ENDPOINT_PATH)
                .method(POST.name())
                .headers(
                        Map.of(
                                AUTHORIZATION,
                                String.format("Bearer %s", bearerToken),
                                CONTENT_TYPE,
                                APPLICATION_JSON.getMimeType(),
                                X_API_KEY_HEADER,
                                SIS_API_KEY))
                .body(getValidRequestBody())
                .willRespondWith()
                .status(httpStatusCode)
                .toPact();
    }

    private static DslPart getValidRequestBody() {
        return newJsonBody(
                        body -> {
                            body.array(
                                    "vtr",
                                    vtr -> {
                                        vtr.stringValue(Vot.P1.name());
                                        vtr.stringValue(Vot.P2.name());
                                    });
                            body.stringValue("govukSigninJourneyId", TEST_JOURNEY_ID);
                        })
                .build();
    }

    private static DslPart getValidResponseBody() {
        return newJsonBody(
                        body -> {
                            body.object(
                                    "content",
                                    siContent -> {
                                        siContent.stringValue("sub", TEST_USER_ID);
                                        siContent.stringValue("vot", Vot.P2.name());
                                        siContent.stringValue("vtm", TEST_VTM);
                                        siContent.array(
                                                "credentials",
                                                credentials -> {
                                                    credentials.stringValue(VC_SIGNATURES.get(0));
                                                    credentials.stringValue(VC_SIGNATURES.get(1));
                                                    credentials.stringValue(VC_SIGNATURES.get(2));
                                                    credentials.stringValue(VC_SIGNATURES.get(3));
                                                });
                                        var jwtBuilder =
                                                new PactJwtBuilder(
                                                        VALID_VC_HEADER,
                                                        VALID_VC_BODY,
                                                        VALID_VC_SIGNATURE);

                                        siContent.minMaxArrayLike(
                                                "https://vocab.account.gov.uk/v1/credentialJWT",
                                                1,
                                                1,
                                                PactDslJsonRootValue.stringMatcher(
                                                        jwtBuilder
                                                                .buildRegexMatcherIgnoringSignature(),
                                                        jwtBuilder.buildJwt()),
                                                1);
                                        siContent.object(
                                                "https://vocab.account.gov.uk/v1/coreIdentity",
                                                identity -> {
                                                    identity.array(
                                                            "name",
                                                            name -> {
                                                                name.object(
                                                                        n -> {
                                                                            n.array(
                                                                                    "nameParts",
                                                                                    nameParts -> {
                                                                                        nameParts
                                                                                                .object(
                                                                                                        np -> {
                                                                                                            np
                                                                                                                    .stringValue(
                                                                                                                            "type",
                                                                                                                            "GivenName");
                                                                                                            np
                                                                                                                    .stringValue(
                                                                                                                            "value",
                                                                                                                            "KENNETH");
                                                                                                        });
                                                                                        nameParts
                                                                                                .object(
                                                                                                        np -> {
                                                                                                            np
                                                                                                                    .stringValue(
                                                                                                                            "type",
                                                                                                                            "FamilyName");
                                                                                                            np
                                                                                                                    .stringValue(
                                                                                                                            "value",
                                                                                                                            "DECERQUEIRA");
                                                                                                        });
                                                                                    });
                                                                        });
                                                            });
                                                    identity.array(
                                                            "birthDate",
                                                            birthDate -> {
                                                                birthDate.object(
                                                                        bd -> {
                                                                            bd.stringValue(
                                                                                    "value",
                                                                                    "1965-07-08");
                                                                        });
                                                            });
                                                });
                                        siContent.array(
                                                "https://vocab.account.gov.uk/v1/passport",
                                                passport -> {
                                                    passport.object(
                                                            p -> {
                                                                p.stringValue(
                                                                        "documentNumber",
                                                                        "321654987");
                                                                p.stringValue(
                                                                        "expiryDate", "2030-01-01");
                                                                p.stringValue(
                                                                        "icaoIssuerCode", "GBR");
                                                            });
                                                });
                                    });
                            body.booleanValue("isValid", true);
                            body.booleanValue("expired", false);
                            body.stringValue("vot", EXPECTED_VOT.name());
                            body.booleanValue("signatureValid", true);
                            body.booleanValue("kidValid", true);
                        })
                .build();
    }

    private static DslPart getMalformedResponse() {
        return newJsonBody(
                        body -> {
                            body.booleanValue("isValid", true);
                            body.booleanValue("expired", false);
                            body.stringValue("vot", Vot.P2.name());
                            body.booleanValue("signatureValid", true);
                            body.booleanValue("kidValid", true);
                        })
                .build();
    }

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
    private static final String VALID_VC_BODY =
            """
            {
                "iss": "dummyPassportComponentId",
                "sub": "test-subject",
                "nbf": 4070908800,
                "vc": {
                    "type": [
                        "VerifiableCredential",
                        "IdentityCheckCredential"
                    ],
                    "credentialSubject": {
                        "birthDate": [
                            {
                                "value": "1932-02-25"
                            }
                        ],
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
                        "passport": [
                            {
                                "documentNumber": "824159121",
                                "icaoIssuerCode": "GBR",
                                "expiryDate": "2030-01-01"
                            }
                        ]
                    },
                    "evidence": [
                        {
                            "type": "IdentityCheck",
                            "txn": "278450f1-75f5-4d0d-9e8e-8bc37a07248d",
                            "strengthScore": 4,
                            "validityScore": 2,
                            "ci": [],
                            "checkDetails": [
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "scenario_1"
                                },
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "record_check"
                                }
                            ],
                            "ciReasons": []
                        }
                    ]
                },
                "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_SIGNATURE =
            "ZmeS-B5HQkQBEOnRogwGVuYORA28YiriPbdeKeGUtwVJ4bmvOAZD5ePNVOKO6788N8TAuYCC1uofV0J1gr_e9g"; // pragma: allowlist secret
}
