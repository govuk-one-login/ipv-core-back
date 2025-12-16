package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
@ExcludeFromGeneratedCoverageReport
@AllArgsConstructor
@Getter
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
    FAILED_JOURNEY_ENGINE_STEP(1022, "Failed to execute journey engine step"),
    MISSING_JOURNEY_EVENT(1023, "Missing journey event in input"),
    FAILED_TO_PARSE_ISSUED_CREDENTIALS(1024, "Failed to parse issued credentials"),
    CREDENTIAL_SUBJECT_MISSING(1025, "Credential subject missing from verified credential"),
    INVALID_SESSION_REQUEST(1026, "Failed to parse the session start request"),
    FAILED_TO_ENCRYPT_JWT(1028, "Failed to encrypt JWT"),
    MISSING_OAUTH_STATE(1030, "Missing OAuth state in callback request"),
    INVALID_OAUTH_STATE(1031, "Invalid OAuth State"),
    UNRECOVERABLE_OAUTH_STATE(1033, "Unable to resolve OAuth State"),
    FAILED_TO_GENERATE_IDENTITY_CLAIM(1034, "Failed to generate the identity claim"),
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
    PENDING_VERIFICATION_EXCEPTION(1051, "Pending face to face verification exception"),
    FAILED_TO_FIND_VISITED_CRI(1052, "Failed to find a visited CRI"),
    FAILED_TO_PARSE_CIMIT_SIGNING_KEY(1053, "Failed to parse CIMIT signing key"),
    UNRECOGNISED_CI_CODE(1054, "Unrecognised CI code"),
    NO_VC_STATUS_FOR_CREDENTIAL_ISSUER(1055, "No VC status found for issuer"),
    FAILED_TO_PARSE_CONFIG(1056, "Failed to parse configuration"),
    FAILED_TO_CORRELATE_DATA(1057, "Failed to correlate data"),
    MISSING_SCORE_TYPE(1058, "Missing score type in request"),
    MISSING_SCORE_THRESHOLD(1059, "Missing score type in request"),
    UNKNOWN_SCORE_TYPE(1060, "Unknown score type in request"),
    FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS(1061, "Failed to parse successful VC Store items."),
    FAILED_TO_GENERATE_NINO_CLAIM(1062, "Failed to generate the NINO claim"),
    MISSING_VTR(1064, "The 'vtr' claim is required and was not provided in the request."),
    NO_IPV_FOR_CRI_OAUTH_SESSION(1065, "No ipvSession for existing CriOAuthSession."),
    FAILED_TO_PARSE_CRI_CALLBACK_REQUEST(1066, "Failed to parse cri callback request."),
    ERROR_PROCESSING_TICF_CRI_RESPONSE(1067, "Error processing response from the TICF CRI"),
    MISSING_IS_RESET_DELETE_GPG45_ONLY_PARAMETER(1068, "Missing deleteOnlyGPG45VCs in request"),
    FAILED_TO_FIND_MITIGATION_ROUTE(1070, "Failed to find mitigation route"),
    FAILED_TO_DELETE_CREDENTIAL(1071, "Failed to delete credential"),
    FAILED_TO_GET_CREDENTIAL(1072, "Failed to get credential"),
    INVALID_JOURNEY_EVENT(1073, "Invalid journey event in input"),
    FAILED_TO_STORE_IDENTITY(1074, "Failed to store identity"),
    MITIGATION_ROUTE_CONFIG_NOT_FOUND(
            1075, "No mitigation journey route event found in cimit config"),
    FAILED_TO_PARSE_EVIDENCE_REQUESTED(1076, "Error parsing evidenceRequest for cri oauth request"),
    RECEIVED_NON_200_RESPONSE_STATUS_CODE(1077, "Non 200 HTTP response status code"),
    FAILED_TO_CONSTRUCT_EVCS_URI(1078, "Failed to construct EVCS uri"),
    FAILED_TO_PARSE_EVCS_RESPONSE(1079, "Failed to parse EVCS response"),
    FAILED_TO_PARSE_EVCS_REQUEST_BODY(1080, "Failed to parse EVCS request body"),
    FAILED_TO_PARSE_EVCS_VC(1081, "Failed to parse a vc from EVCS"),
    FAILED_AT_EVCS_HTTP_REQUEST_SEND(1082, "Failed while sending http request to EVCS"),
    MISSING_IS_COMPLETED_IDENTITY_PARAMETER(1083, "Missing isCompletedIdentity in request"),
    INVALID_IDENTITY_TYPE_PARAMETER(1084, "Invalid or missing identityType in request"),
    MISSING_CHECK_TYPE(1085, "checkType missing from process request"),
    UNKNOWN_CHECK_TYPE(1086, "unknown checkType received"),
    MISSING_RESET_TYPE(1087, "resetType missing from process request"),
    UNKNOWN_RESET_TYPE(1088, "unknown resetType received"),
    ERROR_CALLING_DCMAW_ASYNC_CRI(1089, "Error calling the DCMAW Async CRI"),
    FAILED_TO_UPDATE_IDENTITY(1090, "Failed to update identity"),
    INVALID_SIGNING_KEY_TYPE(1091, "Signing key is invalid type. Must be EC or RSA"),
    UNEXPECTED_CREDENTIAL_TYPE(1092, "Unexpected credential type"),
    IPV_SESSION_NOT_FOUND(
            1093, "Invalid IPV session id provided, corresponding session not found in db"),
    CLIENT_OAUTH_SESSION_NOT_FOUND(1094, "Client OAuth session not found"),
    MISSING_LANGUAGE(1095, "Missing language choice from the frontend"),
    FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE(
            1096, "Failed to validate verifiable credential response"),
    ERROR_MOBILE_APP_RESPONSE_STATUS(1097, "Mobile app cri response has status error"),
    INVALID_PROCESS_MOBILE_APP_JOURNEY_TYPE(1098, "Invalid process mobile app journey type"),
    FAILED_TO_PARSE_MOBILE_APP_CALLBACK_REQUEST_BODY(
            1099, "Failed to parse mobile app callback request body"),
    CRI_RESPONSE_ITEM_NOT_FOUND(1100, "CRI response item cannot be found"),
    MISSING_TARGET_VOT(1101, "Target VOT missing from session"),
    INVALID_VTR_CLAIM(1102, "Invalid VTR claim"),
    MISSING_PROCESS_IDENTITY_TYPE(1103, "Process identity type missing"),
    UNEXPECTED_PROCESS_IDENTITY_TYPE(1104, "Unexpected process identity type"),
    FAILED_TO_GET_CREDENTIAL_ISSUER_FOR_VC(1105, "Failed to get credential issuer for VC"),
    FAILED_TO_EXTRACT_CIS_FROM_VC(1106, "Failed to extract contra-indicators from VC"),
    MISSING_SECURITY_CHECK_CREDENTIAL(1107, "Missing security check credential"),
    FAILED_TO_CREATE_STORED_IDENTITY_FOR_EVCS(1108, "Failed to create stored identity for EVCS"),
    ERROR_CALLING_AIS_API(1109, "Error when calling AIS API"),
    IPV_SESSION_ITEM_EXPIRED(1110, "Session expired."),
    FAILED_NAME_AND_DOB_CORRELATION(1111, "Failed name and DOB correlation");

    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";
    private final int code;
    private final String message;

    @JsonCreator
    public static ErrorResponse forCode(@JsonProperty("code") int code) {
        for (ErrorResponse element : values()) {
            if (element.getCode() == code) {
                return element;
            }
        }
        return null;
    }

    public Map<String, Object> toResponseBody() {
        return Map.of(ERROR, code, ERROR_DESCRIPTION, message);
    }
}
