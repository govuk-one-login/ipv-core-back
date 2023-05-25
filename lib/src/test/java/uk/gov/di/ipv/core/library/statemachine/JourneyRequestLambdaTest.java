package uk.gov.di.ipv.core.library.statemachine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.BaseResponse;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class JourneyRequestLambdaTest {
    @Mock private Context mockContext;

    private static final ObjectMapper mapper = new ObjectMapper();

    private JourneyRequest journeyRequest;

    @BeforeEach
    void setup() {
        journeyRequest =
                JourneyRequest.builder()
                        .journey("/journey/testlambda")
                        .ipvSessionId(UUID.randomUUID().toString())
                        .ipAddress("192.168.0.1")
                        .clientOAuthSessionId(UUID.randomUUID().toString())
                        .featureSet("test")
                        .build();
    }

    @Test
    void returnJourneyResponse() throws Exception {
        var journeyResponse = new JourneyResponse("/journey/next");
        var handler =
                new JourneyRequestLambda() {
                    @Override
                    protected BaseResponse handleRequest(JourneyRequest request, Context context) {
                        assertEquals(journeyRequest, request);
                        assertEquals(context, mockContext);
                        return journeyResponse;
                    }
                };

        var response = makeRequest(handler, journeyRequest, mockContext, JourneyResponse.class);

        assertEquals(journeyResponse, response);
    }

    @Test
    void returnJourneyErrorResponse() throws Exception {
        var journeyResponse =
                new JourneyErrorResponse(
                        "/journey/error",
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_UNHANDLED_EXCEPTION);
        var handler =
                new JourneyRequestLambda() {
                    @Override
                    protected BaseResponse handleRequest(JourneyRequest request, Context context) {
                        assertEquals(journeyRequest, request);
                        assertEquals(context, mockContext);
                        return journeyResponse;
                    }
                };

        var response =
                makeRequest(handler, journeyRequest, mockContext, JourneyErrorResponse.class);

        assertEquals(journeyResponse, response);
    }

    @Test
    void returnJourneyErrorResponseWhenExceptionThrown() throws Exception {
        var journeyResponse =
                new JourneyErrorResponse(
                        "/journey/error",
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_UNHANDLED_EXCEPTION);
        var handler =
                new JourneyRequestLambda() {
                    @Override
                    protected BaseResponse handleRequest(JourneyRequest request, Context context) {
                        throw new RuntimeException("The Lambda went bang!");
                    }
                };

        var response =
                makeRequest(handler, journeyRequest, mockContext, JourneyErrorResponse.class);

        assertEquals(journeyResponse, response);
    }

    @Test
    void returnJourneyErrorResponseWhenInvalidInput() throws Exception {
        var journeyResponse =
                new JourneyErrorResponse(
                        "/journey/error",
                        HttpStatus.SC_BAD_REQUEST,
                        ErrorResponse.FAILED_TO_PARSE_JSON_MESSAGE);
        var handler =
                new JourneyRequestLambda() {
                    @Override
                    protected BaseResponse handleRequest(JourneyRequest request, Context context) {
                        return new JourneyResponse("/journey/next");
                    }
                };

        var response = makeRequest(handler, "{\"ipv....", mockContext, JourneyErrorResponse.class);

        assertEquals(journeyResponse, response);
    }

    private <T extends BaseResponse> T makeRequest(
            RequestStreamHandler handler,
            JourneyRequest request,
            Context context,
            Class<T> classType)
            throws IOException {
        return makeRequest(handler, mapper.writeValueAsString(request), context, classType);
    }

    private <T extends BaseResponse> T makeRequest(
            RequestStreamHandler handler, String request, Context context, Class<T> classType)
            throws IOException {
        try (var inputStream = new ByteArrayInputStream(request.getBytes());
                var outputStream = new ByteArrayOutputStream()) {
            handler.handleRequest(inputStream, outputStream, context);
            return mapper.readValue(outputStream.toString(), classType);
        }
    }
}
