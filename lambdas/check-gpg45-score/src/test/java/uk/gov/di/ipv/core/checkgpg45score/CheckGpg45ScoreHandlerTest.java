package uk.gov.di.ipv.core.checkgpg45score;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class CheckGpg45ScoreHandlerTest {
    private static final ProcessRequest event =
            ProcessRequest.processRequestBuilder()
                    .journey("")
                    .ipAddress("")
                    .ipvSessionId("")
                    .clientOAuthSessionId("")
                    .scoreType("fraud")
                    .scoreThreshold(2)
                    .build();
    @Mock private Context context;
    @InjectMocks private CheckGpg45ScoreHandler CheckGpg45ScoreHandler;

    @Test
    void handlerShouldReturnEmptyMap() {
        Map<String, Object> journeyResponse = CheckGpg45ScoreHandler.handleRequest(event, context);
        assertEquals(Collections.emptyMap(), journeyResponse);
    }
}
