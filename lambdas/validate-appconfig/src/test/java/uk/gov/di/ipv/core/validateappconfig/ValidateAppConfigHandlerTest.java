package uk.gov.di.ipv.core.validateappconfig;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@ExtendWith(MockitoExtension.class)
class ValidateAppConfigHandlerTest {
    @Test
    void validateAppConfigHandlerAcceptsGoodConfig() throws IOException {
        var content = CommonData.class.getResourceAsStream("/test-parameters.yaml");
        System.out.printf(
                "content: %s", new String(content.readAllBytes(), StandardCharsets.UTF_8));
    }
}
