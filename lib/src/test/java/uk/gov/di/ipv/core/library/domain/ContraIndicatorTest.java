package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ContraIndicatorTest {
    private static final Instant BASE_TIME = Instant.now();
    private static final ContraIndicator CI1 =
            ContraIndicator.builder()
                    .contraIndicatorCode("CI1")
                    .issuanceDate(BASE_TIME.minus(2, ChronoUnit.MILLIS))
                    .build();
    private static final ContraIndicator CI2 =
            ContraIndicator.builder()
                    .contraIndicatorCode("CI2")
                    .issuanceDate(BASE_TIME.minus(2, ChronoUnit.SECONDS))
                    .build();
    private static final ContraIndicator CI3 =
            ContraIndicator.builder()
                    .contraIndicatorCode("CI3")
                    .issuanceDate(BASE_TIME.minus(1, ChronoUnit.MILLIS))
                    .build();

    @Test
    void shouldOrderContraIndicatorsOnIssuanceDate() {
        final List<ContraIndicator> testContraIndicators = new ArrayList<>();
        testContraIndicators.add(CI3);
        testContraIndicators.add(CI2);
        testContraIndicators.add(CI1);
        Collections.sort(testContraIndicators);
        assertEquals(List.of(CI2, CI1, CI3), testContraIndicators);
    }
}
