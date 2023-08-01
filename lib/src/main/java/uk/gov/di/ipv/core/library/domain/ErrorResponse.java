package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
@ExcludeFromGeneratedCoverageReport
public enum ErrorResponse {
    MISSING_QUERY_PARAMETERS(1000, "Missing query parameters for auth request"),
    MISSING_AUTHORIZATION_CODE(1003, "Missing authorization code"),
    FAILED_TO_EXCHANGE_AUTHORIZATION_CODE(
            1004, "Failed to exchange the authorization code for an access token"),
    MISSING_CREDENTIAL_ISSUER_ID(1007, "Missing credential issuer id"),
    INVALID_CREDENTIAL_ISSUER_ID(1008, "Invalid credential issuer id"),
    INVALID_TOKEN_REQUEST(1009, "Invalid token request"),
    MISSING_IPV_SESSION_ID(1010, "Missing ipv session id header"),
    FAILED_TO_GET_CREDENTIAL_FROM_ISSUER(1011, "Failed to get credential from issuer"),
    FAILED_TO_SAVE_CREDENTIAL(1012, "Failed to save credential"),
    FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS(
            1013, "Failed to parse oauth2-specific query string parameters"),
    FAILED_TO_PARSE_CREDENTIAL_ISSUER_CONFIG(
            1014, "Failed to parse credential issuers config to credential issuers object"),
    FAILED_TO_GET_SHARED_ATTRIBUTES(1015, "Failed to get Shared Attributes"),
    FAILED_TO_SIGN_SHARED_ATTRIBUTES(1016, "Failed to sign Shared Attributes"),
    INVALID_REDIRECT_URL(1017, "Provided redirect URL is not in those configured for client"),
    INVALID_REQUEST_PARAM(1018, "Invalid request param"),
    FAILED_TO_PARSE_JWK(1019, "Failed to parse JWK"),
    FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL(1020, "Failed to validate verifiable credential"),
    INVALID_SESSION_ID(
            1021,
            "Invalid ipv-session-id has been provided, could not record of that requested session"),
    FAILED_JOURNEY_ENGINE_STEP(1022, "Failed to execute journey engine step"),
    MISSING_JOURNEY_EVENT(1023, "Missing journey event in input"),
    FAILED_TO_PARSE_ISSUED_CREDENTIALS(1024, "Failed to parse issued credentials"),
    CREDENTIAL_SUBJECT_MISSING(1025, "Credential subject missing from verified credential"),
    INVALID_SESSION_REQUEST(1026, "Failed to parse the session start request"),
    FAILED_TO_ENCRYPT_JWT(1028, "Failed to encrypt JWT"),
    MISSING_OAUTH_STATE(1030, "Missing OAuth state in callback request"),
    INVALID_OAUTH_STATE(1031, "Invalid OAuth State"),
    UNRECOVERABLE_OAUTH_STATE(1033, "Unable to resolve OAuth State"),
    FAILED_TO_GENERATE_IDENTIY_CLAIM(1034, "Failed to generate the identity claim"),
    FAILED_TO_GENERATE_ADDRESS_CLAIM(1035, "Failed to generate the address claim"),
    FAILED_TO_GENERATE_PASSPORT_CLAIM(1036, "Failed to generate the passport claim"),
    FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM(1037, "Failed to generate the driving permit claim"),
    FAILED_TO_DETERMINE_CREDENTIAL_TYPE(1038, "Failed to determine type of credential"),
    FAILED_TO_GET_STORED_CIS(1039, "Failed to get stored CIS"),
    FAILED_TO_SEND_AUDIT_EVENT(1040, "Failed to send audit event"),
    FAILED_TO_INITIALISE_STATE_MACHINE(1041, "Failed to initialise state machine"),
    FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS(
            1042, "Failed to generate the proven user identity details"),
    MISSING_SESSION_ID(1043, "Missing ipv session id and client session id in header"),
    MISSING_IP_ADDRESS(1044, "Missing ip address header"),
    FAILED_BIRTHDATE_CORRELATION(1045, "Failed to correlate gathered birth dates"),
    FAILED_NAME_CORRELATION(1046, "Failed to correlate gathered names"),
    FAILED_TO_CONSTRUCT_REDIRECT_URI(1047, "Failed to construct redirect uri"),
    FAILED_TO_PARSE_JSON_MESSAGE(1048, "Failed to parse JSON message"),
    FAILED_UNHANDLED_EXCEPTION(1049, "Unhandled exception"),
    UNEXPECTED_ASYNC_VERIFIABLE_CREDENTIAL(1050, "Unexpected async verifiable credential"),
    PENDING_VERIFICATION_EXCEPTION(1051, "Pending face to face verification exception"),
    FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE(
            1051, "Failed to validate verifiable credential response"),
    FAILED_TO_FIND_VISITED_CRI(1052, "Failed to find a visited CRI"),
    FAILED_TO_PARSE_CIMIT_SIGNING_KEY(1053, "Failed to parse CIMIT signing key"),
    UNRECOGNISED_CI_CODE(1054, "Unrecognised CI code"),
    NO_VC_STATUS_FOR_CREDENTIAL_ISSUER(1055, "No VC status found for issuer");

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

    public String toJsonString() {
        return String.format("{\"code\":%d,\"message\":\"%s\"}", code, message);
    }

    public String getMessage() {
        return message;
    }

    @JsonCreator
    public static ErrorResponse forCode(int code) {
        for (ErrorResponse element : values()) {
            if (element.getCode() == code) {
                return element;
            }
        }
        return null;
    }
}
