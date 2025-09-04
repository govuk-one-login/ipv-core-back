package uk.gov.di.ipv.core.processasynccricredential.pact.dcmawAsyncCri;

import au.com.dius.pact.consumer.MessagePactBuilder;
import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonRootValue;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.consumer.junit5.ProviderType;
import au.com.dius.pact.core.model.annotations.Pact;
import au.com.dius.pact.core.model.messaging.Message;
import au.com.dius.pact.core.model.messaging.MessagePact;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtBuilder;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.getAsyncResponseMessage;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "DcmawAsyncCriProvider")
@MockServerConfig(hostInterface = "localhost")
public class ContractTest {
    @Mock private ConfigService mockConfigService;

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public MessagePact dcmawAsyncMessageContainsValidCredentials(MessagePactBuilder pactBuilder) {
        return pactBuilder
                .given("testId is a valid subject")
                .given("journeyId is a valid govukSigninJourneyId")
                .given("https://vocab.account.gov.uk/v1/credentialJWT contains a VC")
                .expectsToReceive("A valid Dcmaw Async CRI message from SQS")
                .withContent(
                        newJsonBody(
                                        body -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_DCMAW_ASYNC_VC_WITH_PASSPORT_BODY,
                                                            VALID_DCMAW_ASYNC_VC_SIGNATURE);
                                            body.nullValue("error");
                                            body.stringValue("iss", "dcmawAsync");
                                            body.stringValue("sub", "testId");
                                            body.stringType("state", TEST_OAUTH_STATE);
                                            body.nullValue("error_description");
                                            body.minArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "dcmawAsyncMessageContainsValidCredentials",
            providerType = ProviderType.ASYNCH)
    public void dcmawAsyncMessageReturnsValidCredentials(
            List<Message> messageList, MockServer mockServer) throws Exception {
        var credentialValidator =
                new VerifiableCredentialValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        var criConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                credentialValidator
                        .parseAndValidate(
                                TEST_USER,
                                DCMAW_ASYNC,
                                asyncCriResponse.getVerifiableCredentialJWTs(),
                                criConfig.getSigningKey(),
                                criConfig.getComponentId())
                        .forEach(
                                vc -> {
                                    try {
                                        JsonNode credentialSubject =
                                                OBJECT_MAPPER
                                                        .readTree(vc.getClaimsSet().toString())
                                                        .get(VC)
                                                        .get(CREDENTIAL_SUBJECT);

                                        JsonNode nameParts =
                                                credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                        JsonNode birthDateNode =
                                                credentialSubject.get(BIRTH_DATE).get(0);
                                        JsonNode passportNode =
                                                credentialSubject.get(PASSPORT).get(0);

                                        assertEquals(
                                                "GivenName",
                                                nameParts.get(0).get(NAME_TYPE).asText());
                                        assertEquals(
                                                "FamilyName",
                                                nameParts.get(1).get(NAME_TYPE).asText());

                                        assertEquals(
                                                "Kenneth", nameParts.get(0).get(VALUE).asText());
                                        assertEquals(
                                                "Decerqueira",
                                                nameParts.get(1).get(VALUE).asText());

                                        assertEquals(
                                                "2030-01-01",
                                                passportNode.get(EXPIRY_DATE).asText());
                                        assertEquals(
                                                "321654987",
                                                passportNode.get(DOCUMENT_NUMBER).asText());

                                        assertEquals(
                                                "1965-07-08", birthDateNode.get(VALUE).asText());

                                    } catch (JsonProcessingException e) {
                                        throw new RuntimeException(e);
                                    }
                                });
            } catch (VerifiableCredentialException | JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @NotNull
    private static OauthCriConfig getCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/token"))
                .credentialUrl(new URI("http://localhost:" + mockServer.getPort() + "/credential"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(EC_PRIVATE_KEY_JWK)
                .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final String CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String VC = "vc";
    public static final String PASSPORT = "passport";
    public static final String NAME_PARTS = "nameParts";
    public static final String BIRTH_DATE = "birthDate";
    public static final String NAME = "name";
    public static final String EXPIRY_DATE = "expiryDate";
    public static final String DOCUMENT_TYPE = "documentType";
    public static final String VALUE = "value";
    public static final String NAME_TYPE = "type";
    public static final String ISSUE_DATE = "issueDate";
    public static final String ISSUED_BY = "issuedBy";
    public static final String DOCUMENT_NUMBER = "documentNumber";

    private static final String TEST_USER = "testUserId";
    private static final String TEST_OAUTH_STATE = "some-oauth-state";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String TEST_ISSUER = "dcmawAsyncComponentId";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);

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
    private static final String VALID_DCMAW_ASYNC_VC_WITH_PASSPORT_BODY =
            """
                      {
                       "sub": "test-subject",
                       "aud": "dummyDcmawAsyncComponentId",
                       "nbf": 4070908800,
                       "iss": "dummyDcmawAsyncComponentId",
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
                           "socialSecurityRecord": [],
                           "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                           "passport": [
                             {
                               "expiryDate": "2030-01-01",
                               "documentNumber": "321654987"
                             }
                           ]
                         },
                         "evidence": [
                           {
                             "checkDetails": [
                               {
                                 "identityCheckPolicy": "published",
                                 "checkMethod": "vcrypt"
                               },
                               {
                                 "biometricVerificationProcessLevel": 3,
                                 "checkMethod": "bvr"
                               }
                             ],
                             "validityScore": 2,
                             "verificationScore": 3,
                             "strengthScore": 4,
                             "type": "IdentityCheck",
                             "txn": "eda339dd-aa83-495c-a4d4-75021e9415f9"
                           }
                         ]
                       },
                       "jti": "test-jti"
                     }
                    """;

    private static final String VALID_DCMAW_ASYNC_VC_SIGNATURE =
            "i0WXyPJ3ojgUkWreOYrwzq-aDe4Mifr1PCnTgWEZmaN_AjGWNrTrBYUyUD8fx4cnBP-Id_ZXviqEkDLRnf3ipw"; // pragma: allowlist secret
}
