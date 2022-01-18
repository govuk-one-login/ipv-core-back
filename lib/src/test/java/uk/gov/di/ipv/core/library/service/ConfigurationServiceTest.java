package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.getAllServeEvents;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@WireMockTest(httpPort = ConfigurationService.LOCALHOST_PORT)
@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ConfigurationServiceTest {
    public static final String TEST_TOKEN_URL = "testTokenUrl";
    public static final String TEST_CREDENTIAL_URL = "testCredentialUrl";
    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock SSMProvider ssmProvider;

    private ConfigurationService configurationService;

    @BeforeEach
    void setUp() throws URISyntaxException {
        configurationService = new ConfigurationService(ssmProvider);
    }

    @Test
    void usesLocalSSMProviderWhenRunningLocally(WireMockRuntimeInfo wmRuntimeInfo)
            throws JsonProcessingException {
        stubFor(post("/").willReturn(ok()));
        environmentVariables.set("IS_LOCAL", "true");
        environmentVariables.set("AWS_ACCESS_KEY_ID", "ASDFGHJKL");
        environmentVariables.set("AWS_SECRET_ACCESS_KEY", "1234567890987654321");

        systemProperties.set(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");

        SSMProvider ssmProvider = new ConfigurationService().getSsmProvider();
        assertThrows(NullPointerException.class, () -> ssmProvider.get("any-old-thing"));

        HashMap requestBody =
                new ObjectMapper()
                        .readValue(
                                getAllServeEvents().get(0).getRequest().getBodyAsString(),
                                HashMap.class);

        assertEquals("any-old-thing", requestBody.get("Name"));
        assertEquals(false, requestBody.get("WithDecryption"));
    }

    @Test
    void shouldGetCredentialIssuerFromParameterStore() {
        environmentVariables.set("ENVIRONMENT", "dev");

        Map<String, String> credentialIssuerParameters =
                Map.of("tokenUrl", TEST_TOKEN_URL, "credentialUrl", TEST_CREDENTIAL_URL);
        when(ssmProvider.getMultiple("/dev/IPV/Core/CredentialIssuers/PassportCRI"))
                .thenReturn(credentialIssuerParameters);

        CredentialIssuerConfig result = configurationService.getCredentialIssuer("PassportCRI");

        CredentialIssuerConfig expected =
                new CredentialIssuerConfig(
                        "PassportCRI", URI.create(TEST_TOKEN_URL), URI.create(TEST_CREDENTIAL_URL));

        assertEquals(expected.getTokenUrl(), result.getTokenUrl());
        assertEquals(expected.getCredentialUrl(), result.getCredentialUrl());
    }
}
