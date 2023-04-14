package uk.gov.di.ipv.core.library.helpers;

import org.apache.http.HttpStatus;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class StepFunctionHelpers {
    public static final String CODE = "code";
    public static final String IPV_SESSION_ID = "ipvSessionId";
    public static final String JOURNEY = "journey";
    public static final String MESSAGE = "message";
    public static final String STATUS_CODE = "statusCode";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String TYPE = "type";
    public static final String PAGE = "page";

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

    public static String getJourneyStep(Map<String, String> input)
            throws HttpResponseExceptionWithErrorBody {
        String[] parts =
                Optional.ofNullable(input.get(JOURNEY))
                        .orElseThrow(
                                () ->
                                        new HttpResponseExceptionWithErrorBody(
                                                HttpStatus.SC_BAD_REQUEST,
                                                ErrorResponse.MISSING_JOURNEY_STEP))
                        .split("/");
        return parts[parts.length - 1];
    }

    public static Map<String, Object> generateErrorOutputMap(
            int statusCode, JourneyResponse journeyResponse) {
        Map<String, Object> output = new HashMap<>();
        output.put(STATUS_CODE, statusCode);
        output.put(JOURNEY, journeyResponse.getJourney());
        output.put(CODE, journeyResponse.getStatusCode());
        return output;
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
