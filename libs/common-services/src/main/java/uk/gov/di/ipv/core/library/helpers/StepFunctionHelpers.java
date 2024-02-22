package uk.gov.di.ipv.core.library.helpers;

import org.apache.http.HttpStatus;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

public class StepFunctionHelpers {
    private static final String CODE = "code";
    private static final String IPV_SESSION_ID = "ipvSessionId";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";
    private static final String IP_ADDRESS = "ipAddress";
    private static final String TYPE = "type";
    private static final String PAGE = "page";
    private static final String FEATURE_SET = "featureSet";

    private StepFunctionHelpers() {
        throw new IllegalStateException("Utility class");
    }

    public static String getIpvSessionId(Map<String, String> input)
            throws HttpResponseExceptionWithErrorBody {
        String ipvSessionId = input.get(IPV_SESSION_ID);

        if (ipvSessionId == null) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }

        LogHelper.attachIpvSessionIdToLogs(ipvSessionId);

        return ipvSessionId;
    }

    public static String getIpAddress(Map<String, String> input) {
        return input.get(IP_ADDRESS);
    }

    public static List<String> getFeatureSet(Map<String, String> input) {
        String featureSet = input.get(FEATURE_SET);
        LogHelper.attachFeatureSetToLogs(Collections.singletonList(featureSet));
        return (featureSet != null)
                ? Stream.of(featureSet.split(",")).map(String::trim).toList()
                : Collections.emptyList();
    }

    public static String getJourneyEvent(Map<String, String> input)
            throws HttpResponseExceptionWithErrorBody {
        String[] parts =
                Optional.ofNullable(input.get(JOURNEY))
                        .orElseThrow(
                                () ->
                                        new HttpResponseExceptionWithErrorBody(
                                                HttpStatus.SC_BAD_REQUEST,
                                                ErrorResponse.MISSING_JOURNEY_EVENT))
                        .split("/");
        return parts[parts.length - 1];
    }

    public static Map<String, Object> generateErrorOutputMap(
            int statusCode, ErrorResponse errorResponse) {
        Map<String, Object> output = new HashMap<>();
        output.put(STATUS_CODE, statusCode);
        output.put(MESSAGE, errorResponse.getMessage());
        output.put(CODE, errorResponse.getCode());
        return output;
    }

    public static Map<String, Object> generatePageOutputMap(
            String type, int statusCode, String pageId) {
        Map<String, Object> output = new HashMap<>();
        output.put(TYPE, type);
        output.put(STATUS_CODE, statusCode);
        output.put(PAGE, pageId);
        return output;
    }
}
