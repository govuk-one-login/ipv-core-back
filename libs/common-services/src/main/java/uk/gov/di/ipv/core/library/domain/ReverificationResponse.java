package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ReverificationResponse(
        boolean success,
        String sub,
        @JsonProperty("failure_code") String errorCode,
        @JsonProperty("failure_description") String errorDescription) {
    public static ReverificationResponse successResponse(String sub) {
        return new ReverificationResponse(true, sub, null, null);
    }

    public static ReverificationResponse failureResponse(
            String sub, ReverificationFailureCode failureCode, String failureDescription) {
        return new ReverificationResponse(
                false, sub, failureCode.getFailureCode(), failureDescription);
    }
}
