package uk.gov.di.ipv.core.library.sis.client.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.client.SisClient;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityCheckDto;

import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static io.netty.handler.codec.http.HttpMethod.POST;
import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "StoredIdentityProvider")
@MockServerConfig(hostInterface = "localhost")
public class SisContractTest {

    private static final String TEST_SIS_ACCESS_TOKEN = "test-access-token";
    private static final List<Vot> TEST_VOTS = List.of(Vot.P1, Vot.P2);
    private static final String TEST_JOURNEY_ID = "test-gov-journey-id";

    private static final String USER_IDENTITY_PATH = "/user-identity";

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
                .uponReceiving("A request to get existing stored identity record.")
                .path(USER_IDENTITY_PATH)
                .method(POST.name())
                .headers(Map.of(AUTHORIZATION, String.format("Bearer %s", TEST_SIS_ACCESS_TOKEN)))
                .body(getValidRequestBody().toString())
                .willRespondWith()
                .status(200)
                .body(getValidResponseBody())
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
    @PactTestFor(pactMethod = "validGetStoredIdentityRequestReturns200")
    void testPostUserIdentityReturns200(MockServer mockServer) {
        // Arrange
        var underTest = new SisClient(mockConfigService);
        var expectedIdentityDetails =
                new SisStoredIdentityCheckDto("test-content", true, false, Vot.P2, true, true);

        // Act
        var sisGetStoredIdentityResult =
                underTest.getStoredIdentity(TEST_SIS_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertTrue(sisGetStoredIdentityResult.requestSucceeded());
        assertTrue(sisGetStoredIdentityResult.identityWasFound());
        assertEquals(expectedIdentityDetails, sisGetStoredIdentityResult.identityDetails());
    }
}
