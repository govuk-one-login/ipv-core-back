package uk.gov.di.ipv.core.drivinglicensefraudscore;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class DrivingLicenseFraudScoreHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_JOURNEY = "journey/reset-identity";
    private static final JourneyRequest event =
            JourneyRequest.builder()
                    .ipvSessionId(TEST_SESSION_ID)
                    .ipAddress(TEST_CLIENT_SOURCE_IP)
                    .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                    .journey(TEST_JOURNEY)
                    .featureSet(TEST_FEATURE_SET)
                    .build();
    @Mock private Context context;
    @InjectMocks private DrivingLicenseFraudScoreHandler drivingLicenseFraudScoreHandler;

    @Test
    void handlerShouldReturnEmptyMap() {
        Map<String, Object> journeyResponse = drivingLicenseFraudScoreHandler.handleRequest(event, context);
        assertEquals(Collections.emptyMap(), journeyResponse);
    }
}
