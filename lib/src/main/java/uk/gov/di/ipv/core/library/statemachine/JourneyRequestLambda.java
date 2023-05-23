package uk.gov.di.ipv.core.library.statemachine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.library.domain.BaseResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class JourneyRequestLambda implements RequestStreamHandler {
    public static final String JOURNEY_ERROR_PATH = "/journey/error";
    private ObjectMapper mapper = new ObjectMapper();

    @Override
    public void handleRequest(InputStream input, OutputStream output, Context context)
            throws IOException {
        JourneyRequest request = mapper.readValue(input, JourneyRequest.class);
        BaseResponse response = handleRequest(request, context);
        mapper.writeValue(output, response);
    }

    protected abstract BaseResponse handleRequest(JourneyRequest request, Context context);
}
