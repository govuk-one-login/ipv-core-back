package uk.gov.di.ipv.core.library.statemachine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.BaseResponse;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class JourneyRequestLambda implements RequestStreamHandler {
    @java.lang.SuppressWarnings(
            "java:S1075") // These are known addresses used within Process Journey
    public static final String JOURNEY_ERROR_PATH = "/journey/error";

    @java.lang.SuppressWarnings(
            "java:S1075") // These are known addresses used within Process Journey
    public static final String JOURNEY_NEXT_PATH = "/journey/next";

    @java.lang.SuppressWarnings(
            "java:S1075") // These are known addresses used within Process Journey
    public static final String JOURNEY_END_PATH = "/journey/end";

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void handleRequest(InputStream input, OutputStream output, Context context)
            throws IOException {
        JourneyRequest request = null;
        BaseResponse response = null;
        try {
            request = mapper.readValue(input, JourneyRequest.class);
        } catch (Exception e) {
            LOGGER.error("Unable to parse input request", e);
            response =
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_BAD_REQUEST,
                            ErrorResponse.FAILED_TO_PARSE_JSON_MESSAGE,
                            e.getMessage());
        }

        try {
            if (response == null) {
                response = handleRequest(request, context);
            }
        } catch (Exception e) {
            LOGGER.error("Unhandled exception whilst processing Lambda", e);
            response =
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_UNHANDLED_EXCEPTION,
                            e.getMessage());
        }

        mapper.writeValue(output, response);
    }

    protected abstract BaseResponse handleRequest(JourneyRequest request, Context context);
}
