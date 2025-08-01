package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class ConfigServiceTest {

    @Test
    void generateConfigurationCreatesValidConfig() throws IOException, URISyntaxException {
        // Arrange
        String yamlContent =
                Files.readString(
                        Paths.get(
                                ConfigServiceTest.class
                                        .getResource("/test-parameters.yaml")
                                        .toURI()));

        // Act
        var configuration = ConfigService.generateConfiguration(yamlContent);

        // Assert
        assertEquals(
                "https://identity.local.account.gov.uk", configuration.getSelf().getComponentId());
    }

    @Test
    void generateConfigurationThrowsWhenInvalidConfig() throws IOException, URISyntaxException {
        // Arrange
        String yamlContent =
                Files.readString(
                        Paths.get(
                                ConfigServiceTest.class
                                        .getResource("/test-invalid-parameters.yaml")
                                        .toURI()));

        // Act & Assert
        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ConfigService.generateConfiguration(yamlContent));
        assertEquals("Could not load parameters yaml", exception.getMessage());
    }
}
