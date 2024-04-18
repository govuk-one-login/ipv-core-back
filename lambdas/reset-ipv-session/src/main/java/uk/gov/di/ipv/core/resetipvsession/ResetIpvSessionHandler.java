package uk.gov.di.ipv.core.resetipvsession;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;

import java.util.Map;

public class ResetIpvSessionHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest input, Context context) {
        return null;
    }
}
