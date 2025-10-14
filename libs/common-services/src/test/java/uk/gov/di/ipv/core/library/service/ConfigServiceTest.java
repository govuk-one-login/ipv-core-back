package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class ConfigServiceTest {
    @Test
    void generateConfigurationCreatesValidConfig() throws IOException, URISyntaxException {
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
                new URI("https://identity.local.account.gov.uk"),
                configuration.getSelf().getComponentId());
        assertEquals(1800L,
                configuration.getSelf().getDcmawAsyncVcPendingReturnTtl());
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
