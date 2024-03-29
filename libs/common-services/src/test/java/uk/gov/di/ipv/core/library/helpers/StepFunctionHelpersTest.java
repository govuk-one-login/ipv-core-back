package uk.gov.di.ipv.core.library.helpers;

import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StepFunctionHelpersTest {

    private static final String CODE = "code";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";
    private static final String TYPE = "type";
    private static final String PAGE = "page";

    @Test
    void getIpvSessionIdShouldReturnIpvSessionId() throws Exception {
        Map<String, String> input = Map.of("ipvSessionId", "something");

        assertEquals("something", StepFunctionHelpers.getIpvSessionId(input));
    }

    @Test
    void getIpvSessionIdShouldThrowIfIpvSessionIdMissing() {
        Map<String, String> input = Map.of();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> StepFunctionHelpers.getIpvSessionId(input));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID, exception.getErrorResponse());
        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
    }

    @Test
    void getJourneyEventShouldReturnJourneyEvent() throws Exception {
        Map<String, String> input = Map.of("journey", "/journey/next");

        assertEquals("next", StepFunctionHelpers.getJourneyEvent(input));
    }

    @Test
    void getJourneyEventShouldThrowIfJourneyMissing() {
        Map<String, String> input = Map.of();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> StepFunctionHelpers.getJourneyEvent(input));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT, exception.getErrorResponse());
        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
    }

    @Test
    void getIpAddressShouldReturnIpAddress() {
        Map<String, String> input = Map.of("ipAddress", "something");

        assertEquals("something", StepFunctionHelpers.getIpAddress(input));
    }

    @Test
    void generateErrorOutputMapShouldGenerateAnErrorOutputMap() {
        Map<String, Object> expected =
                Map.of(
                        STATUS_CODE, 400,
                        MESSAGE, ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getMessage(),
                        CODE, ErrorResponse.CREDENTIAL_SUBJECT_MISSING.getCode());

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

    @Test
    void getFeatureSetShouldReturnFeatureSet() {
        Map<String, String> input = Map.of("featureSet", "test-feature-set");

        assertEquals(List.of("test-feature-set"), StepFunctionHelpers.getFeatureSet(input));
    }
}
