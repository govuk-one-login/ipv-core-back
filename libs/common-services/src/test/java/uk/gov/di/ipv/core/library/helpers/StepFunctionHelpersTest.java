package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StepFunctionHelpersTest {

    private static final String ERROR_CODE = "errorCode";
    private static final String ERROR_MESSAGE = "errorMessage";
    private static final String STATUS_CODE = "statusCode";
    private static final String TYPE = "type";
    private static final String PAGE = "page";

    @Test
    void generateErrorOutputMapShouldGenerateAnErrorOutputMap() {
        Map<String, Object> expected =
                Map.of(
                        STATUS_CODE, 400,
                        ERROR_MESSAGE, ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getMessage(),
                        ERROR_CODE, ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getCode());

        assertEquals(
                expected,
                StepFunctionHelpers.generateErrorOutputMap(
                        400, ErrorResponse.CREDENTIAL_SUBJECT_MISSING));
    }

    @Test
    void generatePageOutputMapShouldGenerateAPageOutputMap() {
        Map<String, Object> expected =
                Map.of(
                        TYPE, "error",
                        STATUS_CODE, 400,
                        PAGE, "some-page");

        assertEquals(
                expected, StepFunctionHelpers.generatePageOutputMap("error", 400, "some-page"));
    }
}
