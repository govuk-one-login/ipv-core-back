package uk.gov.di.ipv.core.library.helpers;

import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.CODE;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.MESSAGE;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.STATUS_CODE;

class StepFunctionHelpersTest {
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
    void getJourneyStepShouldReturnJourneyStep() throws Exception {
        Map<String, String> input = Map.of("journey", "/journey/next");

        assertEquals("next", StepFunctionHelpers.getJourneyStep(input));
    }

    @Test
    void getJourneyStepShouldThrowIfJourneyMissing() {
        Map<String, String> input = Map.of();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> StepFunctionHelpers.getJourneyStep(input));
        assertEquals(ErrorResponse.MISSING_JOURNEY_STEP, exception.getErrorResponse());
        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
    }

    @Test
    void getClientSourceIpShouldReturnClientSourceIP() throws Exception {
        Map<String, String> input = Map.of("clientSourceIp", "something");

        assertEquals("something", StepFunctionHelpers.getClientSourceIp(input));
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
}
