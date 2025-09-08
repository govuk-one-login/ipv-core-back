package uk.gov.di.ipv.core.library.sis.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
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
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.client.SisClient;
import uk.gov.di.ipv.core.library.sis.client.SisGetStoredIdentityResult;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityCheckDto;

import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static io.netty.handler.codec.http.HttpMethod.POST;
import static org.apache.hc.core5.http.ContentType.APPLICATION_JSON;
import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static org.apache.hc.core5.http.HttpStatus.SC_FORBIDDEN;
import static org.apache.hc.core5.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static org.apache.hc.core5.http.HttpStatus.SC_NOT_FOUND;
import static org.apache.hc.core5.http.HttpStatus.SC_OK;
import static org.apache.hc.core5.http.HttpStatus.SC_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "StoredIdentityProvider")
@MockServerConfig(hostInterface = "localhost")
public class ContractTest {

    private static final String TEST_SIS_ACCESS_TOKEN = "test-access-token";
    private static final String TEST_INVALID_SIS_ACCESS_TOKEN = "test-invalid-access-token";
    private static final String TEST_EXPIRED_SIS_ACCESS_TOKEN = "test-expired-access-token";
    private static final List<Vot> TEST_VOTS = List.of(Vot.P1, Vot.P2);
    private static final String TEST_JOURNEY_ID = "test-gov-journey-id";

    private static final String USER_IDENTITY_PATH = "/user-identity";

    private static final SisGetStoredIdentityResult EXPECTED_INVALID_RESULT =
            new SisGetStoredIdentityResult(false, false, null);

    @Mock ConfigService mockConfigService;

    @BeforeEach
    void setup(MockServer mockServer) {
        when(mockConfigService.getParameter(ConfigurationVariable.SIS_APPLICATION_URL))
                .thenReturn("http://localhost:" + mockServer.getPort());
    }

    @Pact(provider = "StoredIdentityProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetStoredIdentityRequestReturns200(
            PactDslWithProvider builder) {
        return builder.given(String.format("%s is a valid vtr list", TEST_VOTS))
                .given(String.format("%s is a valid journey id", TEST_JOURNEY_ID))
                .uponReceiving("A request to get existing stored identity record (200)")
                .path(USER_IDENTITY_PATH)
                .method(POST.name())
                .headers(AUTHORIZATION, String.format("Bearer %s", TEST_SIS_ACCESS_TOKEN))
                .body(getValidRequestBody())
                .willRespondWith()
                .status(SC_OK)
                .body(getValidResponseBody())
                .toPact();
    }

    private static DslPart getValidResponseBody() {
        return newJsonBody(
                        body -> {
                            body.stringValue("content", "test-content");
                            body.booleanValue("isValid", true);
                            body.booleanValue("expired", false);
                            body.stringValue("vot", Vot.P2.name());
                            body.booleanValue("signatureValid", true);
                            body.booleanValue("kidValid", true);
                        })
                .build();
    }

    @Test
    @DisplayName("POST /user-identity - 200 returns stored identity")
    @PactTestFor(pactMethod = "validGetStoredIdentityRequestReturns200")
    void testGetUserIdentityRequestReturns200(MockServer mockServer) {
        // Arrange
        var sisClient = new SisClient(mockConfigService);
        var expectedIdentityDetails =
                new SisStoredIdentityCheckDto("test-content", true, false, Vot.P2, true, true);
        var expectedValidResult =
                new SisGetStoredIdentityResult(true, true, expectedIdentityDetails);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(expectedValidResult, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns404(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                "(404 no record)", SC_NOT_FOUND, TEST_SIS_ACCESS_TOKEN, builder);
    }

    @Test
    @DisplayName("POST /user-identity - 404 returns empty with successful request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns404")
    void testGetUserIdentityRequestReturns404(MockServer mockServer) {
        // Arrange
        var sisClient = new SisClient(mockConfigService);
        var expectedNotFoundResult = new SisGetStoredIdentityResult(true, false, null);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(expectedNotFoundResult, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns401(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                "(401 unauthorized)", SC_UNAUTHORIZED, TEST_INVALID_SIS_ACCESS_TOKEN, builder);
    }

    @Test
    @DisplayName("POST /user-identity - 401 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns401")
    void testGetUserIdentityRequestReturns401(MockServer mockServer) {
        // Arrange
        var sisClient = new SisClient(mockConfigService);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(
                        TEST_INVALID_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns403(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                "(403 forbidden)", SC_FORBIDDEN, TEST_EXPIRED_SIS_ACCESS_TOKEN, builder);
    }

    @Test
    @DisplayName("POST /user-identity - 403 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns403")
    void testGetUserIdentityRequestReturns403(MockServer mockServer) {
        // Arrange
        var sisClient = new SisClient(mockConfigService);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(
                        TEST_EXPIRED_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns500(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(
                "(500 server error)", SC_INTERNAL_SERVER_ERROR, TEST_SIS_ACCESS_TOKEN, builder);
    }

    @Test
    @DisplayName("POST /user-identity - 500 returns empty with failed request")
    @PactTestFor(pactMethod = "invalidGetStoredIdentityRequestReturns500")
    void testGetUserIdentityRequestReturns500(MockServer mockServer) {
        // Arrange
        var sisClient = new SisClient(mockConfigService);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(EXPECTED_INVALID_RESULT, sisGetStoredIdentityResult);
    }

    private static RequestResponsePact buildStoredIdentityInteraction(
            String description,
            int httpStatusCode,
            String bearerToken,
            PactDslWithProvider builder) {
        return builder.given(String.format("%s is a valid vtr list", TEST_VOTS))
                .given(String.format("%s is a valid journey id", TEST_JOURNEY_ID))
                .uponReceiving(description)
                .path(USER_IDENTITY_PATH)
                .method(POST.name())
                .headers(
                        Map.of(
                                AUTHORIZATION,
                                String.format("Bearer %s", bearerToken),
                                CONTENT_TYPE,
                                APPLICATION_JSON.getMimeType()))
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
}
