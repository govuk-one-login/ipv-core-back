package uk.gov.di.ipv.core.validateappconfig;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class ValidateAppConfigHandlerTest {
    @Mock private Context context;
    @InjectMocks private ValidateAppConfigHandler validateAppConfigHandler;

    private Map<String, Object> getAppConfigRequest(String dataPath) throws IOException {
        var dataBytes = CommonData.class.getResourceAsStream(dataPath).readAllBytes();
        var content = Base64.getEncoder().encodeToString(dataBytes);
        return Map.of("content", content);
    }

    @Test
    void validateAppConfigHandlerAcceptsGoodConfig() throws IOException {
        var request = getAppConfigRequest("/test-parameters.yaml");
        assertDoesNotThrow(() -> validateAppConfigHandler.handleRequest(request, context));
    }

    @Test
    void validateAppConfigHandlerRejectsBadConfig() throws IOException {
        var request = getAppConfigRequest("/test-invalid-parameters.yaml");
        assertThrows(
                Exception.class, () -> validateAppConfigHandler.handleRequest(request, context));
    }
}
