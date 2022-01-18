package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ErrorResponse {
  MISSING_QUERY_PARAMETERS(1000, "Missing query parameters for auth request"),
  MISSING_REDIRECT_URI(1001, "Redirect URI is missing from auth request"),
  FAILED_TO_PARSE_TOKEN_REQUEST(1002, "Failed to parse token request"),
  MISSING_AUTHORIZATION_CODE(1003, "Missing authorization code"),
  FAILED_TO_EXCHANGE_AUTHORIZATION_CODE(
      1004, "Failed to exchange the authorization code for an access token"),
  MISSING_ACCESS_TOKEN(1005, "Missing access token from user info request"),
  FAILED_TO_PARSE_ACCESS_TOKEN(1006, "Failed to parse access token"),
  MISSING_CREDENTIAL_ISSUER_ID(1007, "Missing credential issuer id"),
  INVALID_CREDENTIAL_ISSUER_ID(1008, "Invalid credential issuer id"),
  INVALID_TOKEN_REQUEST(1009, "Invalid token request"),
  MISSING_IPV_SESSION_ID(1010, "Missing ipv session id header"),
  FAILED_TO_GET_CREDENTIAL_FROM_ISSUER(1011, "Failed to get credential from issuer"),
  FAILED_TO_SAVE_CREDENTIAL(1012, "Failed to save credential"),
  FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS(
      1013, "Failed to parse oauth2-specific query string parameters"),
  FAILED_TO_DECODE_CREDENTIAL_ISSUER_CONFIG(
      1014, "Failed to decode credential issuers config to credential issuers object");

  @JsonProperty("code")
  private final int code;

  @JsonProperty("message")
  private final String message;

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
