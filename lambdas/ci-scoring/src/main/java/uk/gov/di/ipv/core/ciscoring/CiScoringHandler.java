package uk.gov.di.ipv.core.ciscoring;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;

import java.util.Collections;
import java.util.Map;

public class CiScoringHandler implements RequestHandler<JourneyRequest, Map<String, Object>> {
    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        return Collections.emptyMap();
    }
}
