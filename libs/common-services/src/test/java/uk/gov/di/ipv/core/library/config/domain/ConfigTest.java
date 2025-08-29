package uk.gov.di.ipv.core.library.config.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigTest {
    private static final String TEST_CLIENT_ID = "orchStub";

    @Test
    void getClientConfigFetchesValidConfig() throws IOException {
        // Arrange
        String yamlContent =
                new String(
                        CommonData.class
                                .getResourceAsStream("/test-parameters.yaml")
                                .readAllBytes(),
                        StandardCharsets.UTF_8);

        // Act
        var configuration = ConfigService.generateConfiguration(yamlContent);

        // Assert
        assertEquals(
                "http://localhost:4500/callback",
                configuration.getClientConfig(TEST_CLIENT_ID).getValidRedirectUrls());
    }
}
