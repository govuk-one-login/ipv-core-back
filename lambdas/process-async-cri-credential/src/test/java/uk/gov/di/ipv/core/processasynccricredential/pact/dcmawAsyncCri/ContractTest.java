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
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtBuilder;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processasynccricredential.domain.ErrorAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.model.IdentityCheckCredential;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.getAsyncResponseMessage;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "DcmawAsyncCriProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    @Mock private ConfigService mockConfigService;

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public MessagePact dcmawAsyncMessageContainsValidCredentials(MessagePactBuilder pactBuilder) {
        return pactBuilder
                .given(String.format("%s is a valid subject", TEST_USER))
                .given(String.format("%s is a valid govukSigninJourneyId", TEST_JOURNEY_ID))
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
                                            body.stringValue("sub", TEST_USER);
                                            body.stringType("state", TEST_OAUTH_STATE);
                                            body.nullValue("error_description");
                                            body.stringValue(
                                                    "govuk_signin_journey_id", TEST_JOURNEY_ID);
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
    void dcmawAsyncMessageReturnsValidCredentials(List<Message> messageList, MockServer mockServer)
            throws Exception {
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
                                    assertInstanceOf(
                                            IdentityCheckCredential.class, vc.getCredential());

                                    var parsedVc = (IdentityCheckCredential) vc.getCredential();
                                    var credentialSubject = parsedVc.getCredentialSubject();

                                    var name = credentialSubject.getName().getFirst();
                                    assertEquals("Kenneth", name.getNameParts().get(0).getValue());
                                    assertEquals(
                                            "Decerqueira", name.getNameParts().get(1).getValue());

                                    var birthDate = credentialSubject.getBirthDate();
                                    assertEquals("1965-07-08", birthDate.getFirst().getValue());

                                    var passport = credentialSubject.getPassport();
                                    assertEquals(
                                            "321654987", passport.getFirst().getDocumentNumber());
                                    assertEquals("2030-01-01", passport.getFirst().getExpiryDate());
                                });
            } catch (VerifiableCredentialException | JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public MessagePact dcmawAsyncMessageContainsValidCredentialsWithCi(
            MessagePactBuilder pactBuilder) {
        return pactBuilder
                .given(String.format("%s is a valid subject", TEST_USER))
                .given(String.format("%s is a valid govukSigninJourneyId", TEST_JOURNEY_ID))
                .given("https://vocab.account.gov.uk/v1/credentialJWT contains a VC")
                .given("the VC has a CI")
                .expectsToReceive("A valid Dcmaw Async CRI message from SQS")
                .withContent(
                        newJsonBody(
                                        body -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_DCMAW_ASYNC_VC_WITH_CI,
                                                            VALID_DCMAW_ASYNC_VC_WITH_CI_SIGNATURE);
                                            body.nullValue("error");
                                            body.stringValue("sub", TEST_USER);
                                            body.stringType("state", TEST_OAUTH_STATE);
                                            body.nullValue("error_description");
                                            body.stringValue(
                                                    "govuk_signin_journey_id", TEST_JOURNEY_ID);
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
            pactMethod = "dcmawAsyncMessageContainsValidCredentialsWithCi",
            providerType = ProviderType.ASYNCH)
    void dcmawAsyncMessageReturnsValidCredentialsWithCi(
            List<Message> messageList, MockServer mockServer) throws Exception {
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("SOME-CI", new ContraIndicatorConfig("SOME-CI", 4, -3, "1")));

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
                                    assertInstanceOf(
                                            IdentityCheckCredential.class, vc.getCredential());

                                    var parsedVc = (IdentityCheckCredential) vc.getCredential();
                                    var credentialSubject = parsedVc.getCredentialSubject();

                                    var name = credentialSubject.getName().getFirst();
                                    assertEquals("Kenneth", name.getNameParts().get(0).getValue());
                                    assertEquals(
                                            "Decerqueira", name.getNameParts().get(1).getValue());

                                    var birthDate = credentialSubject.getBirthDate();
                                    assertEquals("1965-07-08", birthDate.getFirst().getValue());

                                    var passport = credentialSubject.getPassport();
                                    assertEquals(
                                            "321654987", passport.getFirst().getDocumentNumber());

                                    var evidence = parsedVc.getEvidence().getFirst();
                                    assertEquals("SOME-CI", evidence.getCi().getFirst());
                                });
            } catch (VerifiableCredentialException | JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public MessagePact dcmawAsyncMessageContainsError(MessagePactBuilder pactBuilder) {
        return pactBuilder
                .given(String.format("%s is a valid subject", TEST_USER))
                .given(String.format("%s is a valid govukSigninJourneyId", TEST_JOURNEY_ID))
                .given(String.format("the message contains an error %s", TEST_ERROR))
                .given(
                        String.format(
                                "the message contains an error description %s",
                                TEST_ERROR_DESCRIPTION))
                .expectsToReceive("A valid Dcmaw Async CRI message from SQS")
                .withContent(
                        newJsonBody(
                                        body -> {
                                            body.stringValue("error", TEST_ERROR);
                                            body.stringValue("sub", TEST_USER);
                                            body.stringValue("state", TEST_OAUTH_STATE);
                                            body.stringValue(
                                                    "error_description", TEST_ERROR_DESCRIPTION);
                                            body.stringValue(
                                                    "govuk_signin_journey_id", TEST_JOURNEY_ID);
                                            body.nullValue(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "dcmawAsyncMessageContainsError", providerType = ProviderType.ASYNCH)
    void dcmawAsyncMessageReturnsErrorMessage(List<Message> messageList) {
        for (Message message : messageList) {
            try {
                ErrorAsyncCriResponse asyncCriResponse =
                        ((ErrorAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                assertEquals(TEST_ERROR, asyncCriResponse.getError());
                assertEquals(TEST_ERROR_DESCRIPTION, asyncCriResponse.getErrorDescription());
                assertEquals(TEST_USER, asyncCriResponse.getUserId());
                assertEquals(TEST_OAUTH_STATE, asyncCriResponse.getOauthState());
                assertEquals(TEST_JOURNEY_ID, asyncCriResponse.getJourneyId());

            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public MessagePact dcmawAsyncMessageHasInvalidBody(MessagePactBuilder pactBuilder) {
        return pactBuilder
                .given(String.format("%s is a valid subject", TEST_USER))
                .given(String.format("%s is a valid govukSigninJourneyId", TEST_JOURNEY_ID))
                .given(String.format("the message contains an error %s", TEST_ERROR))
                .given(
                        String.format(
                                "the message contains an error description %s",
                                TEST_ERROR_DESCRIPTION))
                .expectsToReceive("A valid Dcmaw Async CRI message from SQS")
                .withContent(
                        newJsonBody(
                                        body -> {
                                            body.stringValue("error", TEST_ERROR);
                                            body.stringValue("sub", TEST_USER);
                                            body.stringValue("state", TEST_OAUTH_STATE);
                                            body.stringValue(
                                                    "error_description", TEST_ERROR_DESCRIPTION);
                                            body.stringValue(
                                                    "unexpected_property",
                                                    "an-unexpected-property");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "dcmawAsyncMessageHasInvalidBody", providerType = ProviderType.ASYNCH)
    void dcmawAsyncMessageWithInvalidBody(List<Message> messageList) {
        for (Message message : messageList) {
            assertThrows(
                    JsonProcessingException.class,
                    () -> getAsyncResponseMessage(message.contentsAsString()));
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

    private static final String TEST_USER = "testId";
    private static final String TEST_OAUTH_STATE = "some-oauth-state";
    private static final String TEST_JOURNEY_ID = "journeyId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String TEST_ISSUER = "dcmawAsyncComponentId";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static final String TEST_ERROR = "some error";
    private static final String TEST_ERROR_DESCRIPTION = "some error description";

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
                       "sub": "testId",
                       "aud": "dcmawAsyncComponentId",
                       "nbf": 4070908800,
                       "iss": "dcmawAsyncComponentId",
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
            "-VBmpln00E8q2KzGuI07jg_WIWkSiA8mn5Iaax8PlNH1mUVcVNi4dE5kRHP2iQt9hefGiYPjDup-e75iBvMJdg"; // pragma: allowlist secret

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_DCMAW_ASYNC_VC_WITH_CI =
            """
                      {
                       "sub": "testId",
                       "aud": "dcmawAsyncComponentId",
                       "nbf": 4070908800,
                       "iss": "dcmawAsyncComponentId",
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
                             "validityScore": 0,
                             "verificationScore": 3,
                             "strengthScore": 4,
                             "type": "IdentityCheck",
                             "txn": "eda339dd-aa83-495c-a4d4-75021e9415f9",
                             "ci": ["SOME-CI"]
                           }
                         ]
                       },
                       "jti": "test-jti"
                     }
                    """;

    private static final String VALID_DCMAW_ASYNC_VC_WITH_CI_SIGNATURE =
            "cWDAxcwEH1F_BM5_extLmegN8ndd1eefUSmI8xxtnzrmZUHWiwO-skkTGyAJQRBPTQqT-w1W4ZbcR7QwISz2VA"; // pragma: allowlist secret
}
