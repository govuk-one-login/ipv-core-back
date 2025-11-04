package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ErrorResponseBody {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();

    private final String message;
    private final Integer code;

    public ErrorResponseBody(String message) {
        this.message = message;
        this.code = null;
    }

    public ErrorResponseBody(String message, ErrorCode code) {
        this.message = message;
        this.code = code.getCode();
    }

    public String toString() {
        try {
            return OBJECT_MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            LOGGER.error("Error serialising error response", e);
            return String.format(
                    "{\"message\": \"Unexpected error\", \"code\": \"%s\"}",
                    ErrorCode.UNEXPECTED_ERROR.getCode());
        }
    }
}
