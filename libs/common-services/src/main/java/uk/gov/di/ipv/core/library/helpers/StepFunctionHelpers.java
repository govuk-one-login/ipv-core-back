package uk.gov.di.ipv.core.library.helpers;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

import java.util.HashMap;
import java.util.Map;

public class StepFunctionHelpers {
    private static final String CODE = "code";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";
    private static final String TYPE = "type";
    private static final String PAGE = "page";

    private StepFunctionHelpers() {
        throw new IllegalStateException("Utility class");
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
