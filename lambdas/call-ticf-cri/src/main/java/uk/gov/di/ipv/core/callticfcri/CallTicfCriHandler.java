package uk.gov.di.ipv.core.callticfcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;

import java.util.Map;

public class CallTicfCriHandler implements RequestHandler<JourneyRequest, Map<String, Object>> {
    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest input, Context context) {
        return null;
    }
}
