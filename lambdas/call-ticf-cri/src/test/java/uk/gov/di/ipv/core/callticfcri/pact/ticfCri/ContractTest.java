package uk.gov.di.ipv.core.callticfcri.pact.ticfCri;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.LambdaDslJsonArray;
import au.com.dius.pact.consumer.dsl.PactDslJsonRootValue;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.callticfcri.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.callticfcri.helpers.JwtTestHelper;
import uk.gov.di.ipv.core.callticfcri.service.TicfCriService;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "TicfCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
class ContractTest {
    private static final String API_PATH = "/risk-assessment";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final String PRIVATE_TICF_SIGNING_KEY =
            """
                    {"kty":"EC","d":"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}
            """;
    private static final String APPLICATION_JSON = "application/json";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static JwtTestHelper dvlaVcJwtHelper;
    private static JwtTestHelper passportVcJwtHelper;
    private static JwtTestHelper dvlaWithCiVcJwtHelper;
    private static JwtTestHelper emptyTicfVcJwtHelper;
    private static JwtTestHelper interventionTicfVcJwtHelper;
    private static JwtTestHelper noInterventionTicfVcJwtHelper;
    private static JwtTestHelper noInterventionWithWarningsTicfVcJwtHelper;

    @Mock ConfigService mockConfigService;

    @BeforeAll
    public static void setup() throws IOException {
        dvlaVcJwtHelper = new JwtTestHelper("dvlaVc");
        passportVcJwtHelper = new JwtTestHelper("passportVc");
        dvlaWithCiVcJwtHelper = new JwtTestHelper("dvlaWithCiVc");
        emptyTicfVcJwtHelper = new JwtTestHelper("ticfVc/empty");
        interventionTicfVcJwtHelper = new JwtTestHelper("ticfVc/intervention");
        noInterventionTicfVcJwtHelper = new JwtTestHelper("ticfVc/noIntervention");
        noInterventionWithWarningsTicfVcJwtHelper =
                new JwtTestHelper("ticfVc/noInterventionWithWarnings");
    }

    @Pact(provider = "TicfCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact requestForUserWithNoInterventions(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(
                        "Provided VC can be validated with {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("TICF VC has no interventions or warnings")
                .given("TICF VC risk assessment has id riskAssessmentId")
                .given("TICF VC issuer is https://ticf.account.gov.uk")
                .given(
                        "TICF VC is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("Time is GMT Thursday, 1 January 2099 00:00:00")
                .uponReceiving("Request for risk assessment for user with no interventions")
                .path(API_PATH)
                .method("POST")
                .headers(
                        "x-api-key", PRIVATE_API_KEY,
                        "Content-Type", APPLICATION_JSON)
                .body(getRequestBody(List.of(passportVcJwtHelper)))
                .willRespondWith()
                .status(200)
                .body(getResponseBody(noInterventionTicfVcJwtHelper))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "requestForUserWithNoInterventions")
    void fetchRiskAssessment_whenCalledWithOneVcOnTicfCri_returnsNoInterventionsTicfVc(
            MockServer mockServer)
            throws TicfCriServiceException, ParseException, URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn(PRIVATE_API_KEY);

        var underTest = getTicfCriService();

        // Act
        List<SignedJWT> ticfVcs =
                underTest.getTicfVc(
                        getClientOAuthSessionItem(),
                        getIpvSessionItem(),
                        List.of(passportVcJwtHelper.buildJwt()));

        // Assert
        var claimsSet = ticfVcs.get(0).getJWTClaimsSet();
        assertThat(claimsSet.getSubject(), is("dummyUserId"));
        assertThat(claimsSet.getAudience().get(0), is("https://identity.account.gov.uk"));
        assertThat(claimsSet.getIssuer(), is("https://ticf.account.gov.uk"));
        assertThat(claimsSet.getClaim("jti"), is("test-jti"));
        assertThat(
                claimsSet.getClaim("vc"),
                is(
                        Map.of(
                                "type",
                                List.of("VerifiableCredential", "RiskAssessmentCredential"),
                                "evidence",
                                List.of(
                                        Map.of(
                                                "type",
                                                "RiskAssessment",
                                                "txn",
                                                "dummyRiskAssessmentId")))));
    }

    @Pact(provider = "TicfCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact requestForUserWithNoInterventionsWithWarnings(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(
                        "Provided VC can be validated with {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("TICF VC has no interventions but has B00 warning")
                .given("TICF VC risk assessment has id riskAssessmentId")
                .given("TICF VC issuer is https://ticf.account.gov.uk")
                .given(
                        "TICF VC is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("Time is GMT Thursday, 1 January 2099 00:00:00")
                .uponReceiving(
                        "Request for risk assessment for user with no interventions with warnings")
                .path(API_PATH)
                .method("POST")
                .headers(
                        "x-api-key", PRIVATE_API_KEY,
                        "Content-Type", APPLICATION_JSON)
                .body(getRequestBody(List.of(passportVcJwtHelper)))
                .willRespondWith()
                .status(200)
                .body(getResponseBody(noInterventionWithWarningsTicfVcJwtHelper))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "requestForUserWithNoInterventionsWithWarnings")
    void fetchRiskAssessment_whenCalledWithOneVcOnTicfCri_returnsNoInterventionsWithWarningsTicfVc(
            MockServer mockServer)
            throws TicfCriServiceException, ParseException, URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("B00", new ContraIndicatorConfig()));

        var underTest = getTicfCriService();

        // Act
        List<SignedJWT> ticfVcs =
                underTest.getTicfVc(
                        getClientOAuthSessionItem(),
                        getIpvSessionItem(),
                        List.of(passportVcJwtHelper.buildJwt()));

        // Assert
        var claimsSet = ticfVcs.get(0).getJWTClaimsSet();
        assertThat(claimsSet.getSubject(), is("dummyUserId"));
        assertThat(claimsSet.getAudience().get(0), is("https://identity.account.gov.uk"));
        assertThat(claimsSet.getIssuer(), is("https://ticf.account.gov.uk"));
        assertThat(claimsSet.getClaim("jti"), is("test-jti"));
        assertThat(
                claimsSet.getClaim("vc"),
                is(
                        Map.of(
                                "type",
                                List.of("VerifiableCredential", "RiskAssessmentCredential"),
                                "evidence",
                                List.of(
                                        Map.of(
                                                "type",
                                                "RiskAssessment",
                                                "txn",
                                                "dummyRiskAssessmentId",
                                                "ci",
                                                List.of("B00"))))));
    }

    @Pact(provider = "TicfCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact requestForUserWithInterventions(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(
                        "Provided VC can be validated with {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("TICF VC has intervention with code 01 and reason 007")
                .given("TICF VC risk assessment has id riskAssessmentId")
                .given("TICF VC issuer is https://ticf.account.gov.uk")
                .given(
                        "TICF VC is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("Time is GMT Thursday, 1 January 2099 00:00:00")
                .uponReceiving("Request for risk assessment for user with interventions")
                .path(API_PATH)
                .method("POST")
                .headers(
                        "x-api-key", PRIVATE_API_KEY,
                        "Content-Type", APPLICATION_JSON)
                .body(getRequestBody(List.of(passportVcJwtHelper)))
                .willRespondWith()
                .status(200)
                .body(getResponseBody(interventionTicfVcJwtHelper))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "requestForUserWithInterventions")
    void fetchRiskAssessment_whenCalledWithOneVcOnTicfCri_returnsInterventionsTicfVc(
            MockServer mockServer)
            throws TicfCriServiceException, ParseException, URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn(PRIVATE_API_KEY);

        var underTest = getTicfCriService();

        // Act
        List<SignedJWT> ticfVcs =
                underTest.getTicfVc(
                        getClientOAuthSessionItem(),
                        getIpvSessionItem(),
                        List.of(passportVcJwtHelper.buildJwt()));

        // Assert
        var claimsSet = ticfVcs.get(0).getJWTClaimsSet();
        assertThat(claimsSet.getSubject(), is("dummyUserId"));
        assertThat(claimsSet.getAudience().get(0), is("https://identity.account.gov.uk"));
        assertThat(claimsSet.getIssuer(), is("https://ticf.account.gov.uk"));
        assertThat(claimsSet.getClaim("jti"), is("test-jti"));
        assertThat(
                claimsSet.getClaim("vc"),
                is(
                        Map.of(
                                "type",
                                List.of("VerifiableCredential", "RiskAssessmentCredential"),
                                "evidence",
                                List.of(
                                        Map.of(
                                                "type",
                                                "RiskAssessment",
                                                "txn",
                                                "dummyRiskAssessmentId",
                                                "intervention",
                                                Map.of(
                                                        "interventionCode",
                                                        "01",
                                                        "interventionReason",
                                                        "007"))))));
    }

    @Pact(provider = "TicfCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact requestForUserTimeouts(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(
                        "Provided VC can be validated with {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("TICF timeouts")
                .given("TICF VC issuer is https://ticf.account.gov.uk")
                .given(
                        "TICF VC is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("Time is GMT Thursday, 1 January 2099 00:00:00")
                .uponReceiving("Request for risk assessment for user where TICF timeouts")
                .path(API_PATH)
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Content-Type",
                        "application/json; charset=UTF-8")
                .body(getRequestBody(List.of(passportVcJwtHelper)))
                .willRespondWith()
                .status(200)
                .body(getResponseBody(emptyTicfVcJwtHelper))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "requestForUserTimeouts")
    void fetchRiskAssessment_whenCalledWithOneVcOnTicfCri_timeouts(MockServer mockServer)
            throws TicfCriServiceException, ParseException, URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn(PRIVATE_API_KEY);

        var underTest = getTicfCriService();

        // Act
        List<SignedJWT> ticfVcs =
                underTest.getTicfVc(
                        getClientOAuthSessionItem(),
                        getIpvSessionItem(),
                        List.of(passportVcJwtHelper.buildJwt()));

        // Assert
        var claimsSet = ticfVcs.get(0).getJWTClaimsSet();
        assertThat(claimsSet.getSubject(), is("dummyUserId"));
        assertThat(claimsSet.getAudience().get(0), is("https://identity.account.gov.uk"));
        assertThat(claimsSet.getIssuer(), is("https://ticf.account.gov.uk"));
        assertThat(claimsSet.getClaim("jti"), is("test-jti"));
        assertThat(
                claimsSet.getClaim("vc"),
                is(
                        Map.of(
                                "type",
                                List.of("VerifiableCredential", "RiskAssessmentCredential"),
                                "evidence",
                                List.of(Map.of("type", "RiskAssessment")))));
    }

    @Pact(provider = "TicfCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact requestForUserProvidedMultipleVcs(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(
                        "Provided VCs can be validated with {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("TICF VC has no interventions or warnings")
                .given("TICF VC risk assessment has id riskAssessmentId")
                .given("TICF VC issuer is https://ticf.account.gov.uk")
                .given(
                        "TICF VC is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("Time is GMT Thursday, 1 January 2099 00:00:00")
                .uponReceiving(
                        "Request for risk assessment for user with no interventions provided multiple VCs")
                .path(API_PATH)
                .method("POST")
                .headers(
                        "x-api-key", PRIVATE_API_KEY,
                        "Content-Type", APPLICATION_JSON)
                .body(getRequestBody(List.of(dvlaVcJwtHelper, passportVcJwtHelper)))
                .willRespondWith()
                .status(200)
                .body(getResponseBody(noInterventionTicfVcJwtHelper))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "requestForUserProvidedMultipleVcs")
    void fetchRiskAssessment_whenCalledWithMultipleVcsOnTicfCri_returnsNoInterventionsTicfVc(
            MockServer mockServer)
            throws TicfCriServiceException, ParseException, URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn(PRIVATE_API_KEY);

        var underTest = getTicfCriService();

        // Act
        List<SignedJWT> ticfVcs =
                underTest.getTicfVc(
                        getClientOAuthSessionItem(),
                        getIpvSessionItem(),
                        List.of(dvlaVcJwtHelper.buildJwt(), passportVcJwtHelper.buildJwt()));

        // Assert
        var claimsSet = ticfVcs.get(0).getJWTClaimsSet();
        assertThat(claimsSet.getSubject(), is("dummyUserId"));
        assertThat(claimsSet.getAudience().get(0), is("https://identity.account.gov.uk"));
        assertThat(claimsSet.getIssuer(), is("https://ticf.account.gov.uk"));
        assertThat(claimsSet.getClaim("jti"), is("test-jti"));
        assertThat(
                claimsSet.getClaim("vc"),
                is(
                        Map.of(
                                "type",
                                List.of("VerifiableCredential", "RiskAssessmentCredential"),
                                "evidence",
                                List.of(
                                        Map.of(
                                                "type",
                                                "RiskAssessment",
                                                "txn",
                                                "dummyRiskAssessmentId")))));
    }

    // Identity reuse journey
    @Pact(provider = "TicfCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact requestForUserProvidedNoVcs(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("TICF VC has no interventions or warnings")
                .given("TICF VC risk assessment has id riskAssessmentId")
                .given("TICF VC issuer is https://ticf.account.gov.uk")
                .given(
                        "TICF VC is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("Time is GMT Thursday, 1 January 2099 00:00:00")
                .uponReceiving(
                        "Request for risk assessment for user with no interventions provided no VCs")
                .path(API_PATH)
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY)
                .body(getRequestBody(List.of()))
                .willRespondWith()
                .status(200)
                .body(getResponseBody(noInterventionTicfVcJwtHelper))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "requestForUserProvidedNoVcs")
    void fetchRiskAssessment_whenCalledWithNoVcsOnTicfCri_returnsNoInterventionsTicfVc(
            MockServer mockServer)
            throws TicfCriServiceException, ParseException, URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn(PRIVATE_API_KEY);

        var underTest = getTicfCriService();

        // Act
        List<SignedJWT> ticfVcs =
                underTest.getTicfVc(getClientOAuthSessionItem(), getIpvSessionItem(), List.of());

        // Assert
        var claimsSet = ticfVcs.get(0).getJWTClaimsSet();
        assertThat(claimsSet.getSubject(), is("dummyUserId"));
        assertThat(claimsSet.getAudience().get(0), is("https://identity.account.gov.uk"));
        assertThat(claimsSet.getIssuer(), is("https://ticf.account.gov.uk"));
        assertThat(claimsSet.getClaim("jti"), is("test-jti"));
        assertThat(
                claimsSet.getClaim("vc"),
                is(
                        Map.of(
                                "type",
                                List.of("VerifiableCredential", "RiskAssessmentCredential"),
                                "evidence",
                                List.of(
                                        Map.of(
                                                "type",
                                                "RiskAssessment",
                                                "txn",
                                                "dummyRiskAssessmentId")))));
    }

    // F2F
    @Pact(provider = "TicfCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact requestForUserWithNoInterventionsWithWarningsProvidedVcWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(
                        "Provided VC can be validated with {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("TICF VC has no interventions but has B00 warning")
                .given("TICF VC risk assessment has id riskAssessmentId")
                .given("TICF VC issuer is https://ticf.account.gov.uk")
                .given(
                        "TICF VC is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given("Time is GMT Thursday, 1 January 2099 00:00:00")
                .uponReceiving(
                        "Request for uplift risk assessment for user with no interventions with warnings provided VC with CI")
                .path(API_PATH)
                .method("POST")
                .headers(
                        "x-api-key", PRIVATE_API_KEY,
                        "Content-Type", APPLICATION_JSON)
                .body(getRequestBody(List.of(dvlaWithCiVcJwtHelper)))
                .willRespondWith()
                .status(200)
                .body(getResponseBody(noInterventionWithWarningsTicfVcJwtHelper))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "requestForUserWithNoInterventionsWithWarningsProvidedVcWithCi")
    void
            fetchRiskAssessment_whenCalledWithOneVcWithCiOnTicfCri_returnsNoInterventionsWithWarningsTicfVc(
                    MockServer mockServer)
                    throws TicfCriServiceException, ParseException, URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("B00", new ContraIndicatorConfig()));

        var underTest = getTicfCriService();

        // Act
        List<SignedJWT> ticfVcs =
                underTest.getTicfVc(
                        getClientOAuthSessionItem(),
                        getIpvSessionItem(),
                        List.of(dvlaWithCiVcJwtHelper.buildJwt()));

        // Assert
        var claimsSet = ticfVcs.get(0).getJWTClaimsSet();
        assertThat(claimsSet.getSubject(), is("dummyUserId"));
        assertThat(claimsSet.getAudience().get(0), is("https://identity.account.gov.uk"));
        assertThat(claimsSet.getIssuer(), is("https://ticf.account.gov.uk"));
        assertThat(claimsSet.getClaim("jti"), is("test-jti"));
        assertThat(
                claimsSet.getClaim("vc"),
                is(
                        Map.of(
                                "type",
                                List.of("VerifiableCredential", "RiskAssessmentCredential"),
                                "evidence",
                                List.of(
                                        Map.of(
                                                "type",
                                                "RiskAssessment",
                                                "txn",
                                                "dummyRiskAssessmentId",
                                                "ci",
                                                List.of("B00"))))));
    }

    @NotNull
    private TicfCriService getTicfCriService() {
        var verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));
        return new TicfCriService(mockConfigService, verifiableCredentialJwtValidator);
    }

    private DslPart getRequestBody(List<JwtTestHelper> jwtTestHelpers) {
        return newJsonBody(
                        (body) -> {
                            body.stringType("sub", "dummyUserId");
                            body.minArrayLike("vtr", 1, PactDslJsonRootValue.stringType("P2"), 1);
                            body.stringValue("vot", "P2");
                            body.stringValue("vtm", "https://oidc.account.gov.uk/trustmark");
                            body.stringValue(
                                    "govuk_signin_journey_id", "dummyGovukSigninJourneyId");
                            body.array(
                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                    (LambdaDslJsonArray array) -> {
                                        for (JwtTestHelper jwtTestHelper : jwtTestHelpers) {
                                            array.stringValue(jwtTestHelper.buildJwt());
                                        }
                                    });
                        })
                .build();
    }

    private DslPart getResponseBody(JwtTestHelper jwtTestHelper) {
        return newJsonBody(
                        (body) -> {
                            body.stringValue("sub", "dummyUserId");
                            body.minArrayLike("vtr", 1, PactDslJsonRootValue.stringType("P2"), 1);
                            body.stringValue("vot", "P2");
                            body.stringValue("vtm", "https://oidc.account.gov.uk/trustmark");
                            body.stringValue(
                                    "govuk_signin_journey_id", "dummyGovukSigninJourneyId");
                            body.minArrayLike(
                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                    1,
                                    PactDslJsonRootValue.stringMatcher(
                                            jwtTestHelper.buildRegexMatcherIgnoringSignature(),
                                            jwtTestHelper.buildJwt()),
                                    1);
                        })
                .build();
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .userId("dummyUserId")
                .vtr(List.of("P2"))
                .govukSigninJourneyId("dummyGovukSigninJourneyId")
                .build();
    }

    private IpvSessionItem getIpvSessionItem() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setVot(Vot.P2);

        return ipvSessionItem;
    }

    private static RestCriConfig getMockCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return RestCriConfig.builder()
                .signingKey(PRIVATE_TICF_SIGNING_KEY)
                .componentId("https://ticf.account.gov.uk")
                .credentialUrl(
                        new URI("http://localhost:" + mockServer.getPort() + "/risk-assessment"))
                .requiresApiKey(true)
                .build();
    }
}
