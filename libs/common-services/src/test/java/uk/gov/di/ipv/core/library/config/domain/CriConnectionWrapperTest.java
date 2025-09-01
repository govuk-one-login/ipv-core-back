package uk.gov.di.ipv.core.library.config.domain;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CriConnectionWrapperTest {

    @Test
    void getActiveConfigFetchesValidConfig() throws IOException {
        // Arrange
        String yamlContent =
                new String(
                        CommonData.class
                                .getResourceAsStream("/test-parameters.yaml")
                                .readAllBytes(),
                        StandardCharsets.UTF_8);

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
