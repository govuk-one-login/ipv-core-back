package uk.gov.di.ipv.core.library.config.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CriConnectionWrapperTest {

    @Test
    void getActiveConfigFetchesValidConfig() throws URISyntaxException, IOException {
        // Arrange
        String yamlContent =
                Files.readString(
                        Paths.get(
                                CriConnectionWrapperTest.class
                                        .getResource("/test-parameters.yaml")
                                        .toURI()));

        // Act
        var criConnectionWrapper =
                ConfigService.generateConfiguration(yamlContent)
                        .getCredentialIssuers()
                        .getAddress();

        // Assert
        assertEquals(
                "https://address-cri.stubs.account.gov.uk/authorize",
                criConnectionWrapper.getActiveConfig().getAuthorizeUrl().toString());
    }
}
