package uk.gov.di.ipv.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ErrorResponse {
    MissingQueryParameters(1000, "Missing query parameters for auth request"),
    MissingRedirectURI(1001, "Redirect URI is missing from auth request"),
    FailedToParseTokenRequest(1002, "Failed to parse token request"),
    MissingAuthorizationCode(1003, "Missing authorization code"),
    FailedToExchangeAuthorizationCode(1004, "Failed to exchange the authorization code for an access token"),
    MissingAccessToken(1005, "Missing access token from user info request"),
    FailedToParseAccessToken(1006, "Failed to parse access token"),
    MissingCredentialIssuerId(1007, "Missing credential issuer id"),
    InvalidCredentialIssuerId(1008, "Invalid credential issuer id"),
    InvalidTokenRequest(1009, "Invalid token request");

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
