package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class ConfigServiceTest {

    @Test
    void generateConfigurationCreatesValidConfig() throws IOException {
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
                "https://identity.local.account.gov.uk", configuration.getSelf().getComponentId());
    }

    @Test
    void generateConfigurationThrowsWhenInvalidConfig() throws IOException {
        // Arrange
        String yamlContent =
                new String(
                        CommonData.class
                                .getResourceAsStream("/test-invalid-parameters.yaml")
                                .readAllBytes(),
                        StandardCharsets.UTF_8);

        // Act & Assert
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ConfigService.generateConfiguration(yamlContent));
        assertEquals("Could not load parameters yaml", exception.getMessage());
    }

    @Test
    void generateConfigurationThrowsWhenConfigIsEmpty() {
        String yamlContent = "";
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ConfigService.generateConfiguration(yamlContent));
        assertEquals("Missing Core config.", exception.getMessage());
    }
}
