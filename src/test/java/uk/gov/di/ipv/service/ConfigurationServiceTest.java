package uk.gov.di.ipv.service;

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
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuers;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Set;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@WireMockTest(httpPort = ConfigurationService.LOCALHOST_PORT)
@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ConfigurationServiceTest {

    public static final String CREDENTIAL_ISSUER_CONFIG_BASE64_VERSION_1 =
            "Y3JlZGVudGlhbElzc3VlckNvbmZpZ3M6CiAgLSBpZDogUGFzc3BvcnRJc3N1ZXIKICAgIHRva2VuVXJsOiBodHRwOi8vd3d3LmJvYi5jb20KICAgIGNyZWRlbnRpYWxVcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20vY3JlZGVudGlhbAogIC0gaWQ6IEZyYXVkSXNzdWVyCiAgICB0b2tlblVybDogaHR0cDovL3d3dy5leGFtcGxlLmNvbQogICAgY3JlZGVudGlhbFVybDogaHR0cDovL3d3dy5leGFtcGxlLmNvbS9jcmVkZW50aWFsCg==";

    public static final String CREDENTIAL_ISSUER_CONFIG_BASE64_VERSION_2 =
            "Y3JlZGVudGlhbElzc3VlckNvbmZpZ3M6CiAgLSBpZDogUGFzc3BvcnRJc3N1ZXIKICAgIHRva2VuVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tCiAgICBjcmVkZW50aWFsVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tL2NyZWRlbnRpYWwKICAtIGlkOiBGcmF1ZElzc3VlcgogICAgdG9rZW5Vcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20KICAgIGNyZWRlbnRpYWxVcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20vY3JlZGVudGlhbA==";

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock SSMProvider ssmProvider;

    private CredentialIssuers credentialIssuers;

    @BeforeEach
    void setUp() throws URISyntaxException {
        credentialIssuers =
                new CredentialIssuers(
                        Set.of(
                                new CredentialIssuerConfig(
                                        "PassportIssuer",
                                        new URI("http://www.example.com"),
                                        new URI("http://www.example.com/credential")),
                                new CredentialIssuerConfig(
                                        "FraudIssuer",
                                        new URI("http://www.example.com"),
                                        new URI("http://www.example.com/credential"))),
                        CREDENTIAL_ISSUER_CONFIG_BASE64_VERSION_1);
    }

    @Test
    void shouldReturnDifferentCredentialIssuersWhenBase64EncodingHasChanged() {
        ConfigurationService underTest = new ConfigurationService(ssmProvider);
        when(ssmProvider.get(any()))
                .thenReturn(
                        CREDENTIAL_ISSUER_CONFIG_BASE64_VERSION_1,
                        CREDENTIAL_ISSUER_CONFIG_BASE64_VERSION_2);

        CredentialIssuers credentialIssuers1 = underTest.getCredentialIssuers(credentialIssuers);
        CredentialIssuers credentialIssuers2 = underTest.getCredentialIssuers(credentialIssuers);

        assertNotEquals(credentialIssuers1, credentialIssuers2);
    }

    @Test
    void shouldReturnSameCredentialIssuersWhenBase64EncodingHasNotChanged() {
        ConfigurationService underTest = new ConfigurationService(ssmProvider);
        when(ssmProvider.get(any()))
                .thenReturn(
                        CREDENTIAL_ISSUER_CONFIG_BASE64_VERSION_1,
                        CREDENTIAL_ISSUER_CONFIG_BASE64_VERSION_1);

        CredentialIssuers credentialIssuers1 = underTest.getCredentialIssuers(credentialIssuers);
        CredentialIssuers credentialIssuers2 = underTest.getCredentialIssuers(credentialIssuers);

        assertSame(credentialIssuers1, credentialIssuers2);
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

        assertThrows(
                Exception.class,
                () -> new ConfigurationService().getSsmProvider().get("any-old-thing"));

        HashMap<String, Object> requestBody =
                new ObjectMapper()
                        .readValue(
                                getAllServeEvents().get(0).getRequest().getBodyAsString(),
                                HashMap.class);

        assertEquals("any-old-thing", requestBody.get("Name"));
        assertEquals(false, requestBody.get("WithDecryption"));
    }
}
