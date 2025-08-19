package uk.gov.di.ipv.core.library.config.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigTest {
    private static final String TEST_CLIENT_ID = "orchStub";

    @Test
    void getClientConfigFetchesValidConfig() throws URISyntaxException, IOException {
        // Arrange
        String yamlContent =
                Files.readString(
                        Paths.get(ConfigTest.class.getResource("/test-parameters.yaml").toURI()));

        // Act
        var configuration = ConfigService.generateConfiguration(yamlContent);

        // Assert
        assertEquals(
                "http://localhost:4500/callback",
                configuration.getClientConfig(TEST_CLIENT_ID).getValidRedirectUrls());
    }
}
