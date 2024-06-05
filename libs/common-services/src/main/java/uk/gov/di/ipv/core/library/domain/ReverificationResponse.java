package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ReverificationResponse(
        boolean success,
        String sub,
        @JsonProperty("error_code") String errorCode,
        @JsonProperty("error_description") String errorDescription) {
    public static ReverificationResponse successResponse(String sub) {
        return new ReverificationResponse(true, sub, null, null);
    }

    public static ReverificationResponse failureResponse(
            String sub, String errorCode, String errorDescription) {
        return new ReverificationResponse(false, sub, errorCode, errorDescription);
    }
}
