package uk.gov.di.ipv.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ErrorResponse {
    ERROR_1000(1000, "Missing query parameters for auth request"),
    ERROR_1001(1001, "Redirect URI is missing from auth request"),
    ERROR_1002(1002, "Failed to parse token request"),
    ERROR_1003(1003, "Missing authorisation code for token request"),
    ERROR_1004(1004, "Missing access token from user info request"),
    ERROR_1005(1005, "Failed to parse access token");

    @JsonProperty("code")
    private int code;

    @JsonProperty("message")
    private String message;

    ErrorResponse(
            @JsonProperty(required = true, value = "code") int code,
            @JsonProperty(required = true, value = "message") String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
