package uk.gov.di.ipv.core.storeidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;

import java.util.Map;

public class StoreIdentityHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    @Override
    public Map<String, Object> handleRequest(ProcessRequest input, Context context) {
        return null;
    }
}
