package uk.gov.di.ipv.core.library.evcs.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static org.mockito.Mockito.when;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "EvcsProvider")
@MockServerConfig(hostInterface = "localhost")
public class StoredIdentityServiceContractTest {

    @Mock ConfigService mockConfigService;

    @BeforeEach
    void setup(MockServer mockServer) {

        when(mockConfigService.getParameter(
                        ConfigurationVariable.STORED_IDENTITY_SERVICE_COMPONENT_ID))
                .thenReturn("http://localhost:" + mockServer.getPort());
    }

    @Pact(provider = "StoredIdentityService", consumer = "IpvCoreBack")
    public RequestResponsePact validRetrive(PactDslWithProvider builder) {
        return builder.given("something")
                .uponReceiving("A request to get stored identity record.")
                .path("/user-identity")
                .method("POST")
                .headers(Map.of("Authorization", "Bearer " + "token"))
                .willRespondWith()
                .status(200)
                .body("some body")
                .toPact();
    }
}
