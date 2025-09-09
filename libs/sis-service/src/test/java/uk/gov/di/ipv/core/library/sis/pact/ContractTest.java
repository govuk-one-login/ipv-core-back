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
@PactTestFor(providerName = "StoredIdentityServiceProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {

    private static final String TEST_SIS_ACCESS_TOKEN = "test-access-token";
    private static final String TEST_INVALID_SIS_ACCESS_TOKEN = "test-invalid-access-token";
    private static final String TEST_EXPIRED_SIS_ACCESS_TOKEN = "test-expired-access-token";
    private static final List<Vot> TEST_VOTS = List.of(Vot.P1, Vot.P2);
    private static final String TEST_JOURNEY_ID = "test-gov-journey-id";

    private static final String USER_IDENTITY_ENDPOINT_PATH = "/user-identity";

    private static final String CONTENT_JWT =
            "eyJraWQiOiJ0ZXN0LXNpZ25pbmcta2V5IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOiJodHRwczovL3JldXNlLWlkZW50aXR5LmJ1aWxkLmFjY291bnQuZ292LnVrIiwic3ViIjoiZWFlMDFhYzI5MGE5ODRkMGVhN2MzM2NjNDVlMzZmMTIiLCJuYmYiOjE3NTA2ODIwMTgsImNyZWRlbnRpYWxzIjpbIk43UHhoZmtGa215VFFGS3lBWE15U19INk51Ri13RHpFa3RiX2RWdXJ1bFNSTU1YaG54aGJSMnJ4czlUYy1LUUIwaVhiMV85YUJJOFhDeTJBYkdRdkZRIiwiUzROSlBjaWltYmZ4MDhqczltOThoc3JLTDRiSkh0QlF5S0d0cmRJeklmWW1CUGpyVTlwYXpfdV8xaENySFo4aWp5UW81UlBtUWxNUC1fYzVldXZaSHciLCJBOU9IdUtJOE41aDRDNDU3UTRxdE52a1NGS2ZGZVZNNHNFR3dxUlBjU0hpUXlsemh4UnlxMDBlMURVUUxtU2RpZTlYSWswQ2ZpUVNBX3I3LW1tQ2JBdyIsInk0NHYwcEVBODh6dURoREZEQ0RjUGduOTZwOWJTRm9qeHZQQTFCeEdYTnhEMG5QelFONk1SaG1PWXBTUXg4TW92XzNLWUF4bmZ5aXdSemVBclhKa3FBIl0sImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkubG9jYWwuYWNjb3VudC5nb3YudWsiLCJjbGFpbXMiOnsiaHR0cHM6Ly92b2NhYi5hY2NvdW50Lmdvdi51ay92MS9jb3JlSWRlbnRpdHkiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NjUtMDctMDgifV19LCJodHRwczovL3ZvY2FiLmFjY291bnQuZ292LnVrL3YxL2FkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwiYnVpbGRpbmdOYW1lIjoiIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJzdWJCdWlsZGluZ05hbWUiOiIiLCJ1cHJuIjoxMDAxMjAwMTIwNzcsInZhbGlkRnJvbSI6IjEwMDAtMDEtMDEifV0sImh0dHBzOi8vdm9jYWIuYWNjb3VudC5nb3YudWsvdjEvcGFzc3BvcnQiOlt7ImRvY3VtZW50TnVtYmVyIjoiMzIxNjU0OTg3IiwiZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJpY2FvSXNzdWVyQ29kZSI6IkdCUiJ9XX0sInZvdCI6IlAyIiwiaWF0IjoxNzUwNjgyMDE4fQ.nrbiwaOcvWM92TTAlORzerjjrrCuYD9fcxwEoXbf71J3YZUnwNW0KGUN5jaEvOysG0YWTXSLl_W4sN-Krf7PfQ"; // pragma: allowlist secret

    private static final SisGetStoredIdentityResult EXPECTED_INVALID_RESULT =
            new SisGetStoredIdentityResult(false, false, null);

    @Mock private ConfigService mockConfigService;
    private SisClient sisClient;

    @BeforeEach
    void setup(MockServer mockServer) {
        when(mockConfigService.getParameter(ConfigurationVariable.SIS_APPLICATION_URL))
                .thenReturn("http://localhost:" + mockServer.getPort());
        sisClient = new SisClient(mockConfigService);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetStoredIdentityRequestReturns200(
            PactDslWithProvider builder) {
        return builder.given(String.format("%s is a valid vtr list", TEST_VOTS))
                .given(String.format("%s is a valid journey id", TEST_JOURNEY_ID))
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
                .body(getValidResponseBody())
                .toPact();
    }

    private static DslPart getValidResponseBody() {
        return newJsonBody(
                        body -> {
                            body.stringValue("content", CONTENT_JWT);
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
        var expectedIdentityDetails =
                new SisStoredIdentityCheckDto(CONTENT_JWT, true, false, Vot.P2, true, true);
        var expectedValidResult =
                new SisGetStoredIdentityResult(true, true, expectedIdentityDetails);

        // Act
        var sisGetStoredIdentityResult =
                sisClient.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(expectedValidResult, sisGetStoredIdentityResult);
    }

    @Pact(provider = "StoredIdentityServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetStoredIdentityRequestReturns404(
            PactDslWithProvider builder) {
        return buildStoredIdentityInteraction(SC_NOT_FOUND, TEST_SIS_ACCESS_TOKEN, builder);
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
                SC_UNAUTHORIZED, TEST_INVALID_SIS_ACCESS_TOKEN, builder);
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
        return buildStoredIdentityInteraction(SC_FORBIDDEN, TEST_EXPIRED_SIS_ACCESS_TOKEN, builder);
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
                SC_INTERNAL_SERVER_ERROR, TEST_SIS_ACCESS_TOKEN, builder);
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

    private static RequestResponsePact buildStoredIdentityInteraction(
            int httpStatusCode, String bearerToken, PactDslWithProvider builder) {
        return builder.given(String.format("%s is a valid vtr list", TEST_VOTS))
                .given(String.format("%s is a valid journey id", TEST_JOURNEY_ID))
                .uponReceiving("A request to get user stored identity")
                .path(USER_IDENTITY_ENDPOINT_PATH)
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
