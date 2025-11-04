package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Getter
@JsonInclude(value = JsonInclude.Include.NON_NULL)
public class ErrorResponseBody {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();

    @JsonProperty private final String message;
    @JsonProperty private final Integer code;

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
