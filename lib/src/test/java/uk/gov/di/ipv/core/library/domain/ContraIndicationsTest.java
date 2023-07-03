package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ContraIndicationsTest {
    private ContraIndications contraIndications;
    private static final String TEST_CI1 = "CI1";
    private static final String TEST_CI2 = "CI2";
    private static final String TEST_CI3 = "CI3";
    private static final Instant BASE_TIME = Instant.now();
    private static final Map<String, ContraIndicatorScore> CONTRA_INDICATOR_SCORE_MAP =
            Map.of(
                    TEST_CI1,
                    new ContraIndicatorScore(TEST_CI1, 4, -3, null, null),
                    TEST_CI2,
                    new ContraIndicatorScore(TEST_CI2, 3, -3, null, null),
                    TEST_CI3,
                    new ContraIndicatorScore(TEST_CI3, 2, -1, null, null));

    @BeforeEach
    void setup() {
        contraIndications =
                ContraIndications.builder()
                        .contraIndicatorScores(CONTRA_INDICATOR_SCORE_MAP)
                        .contraIndicators(Map.of())
                        .build();
    }

    @Test
    void shouldReturnZeroScoreForEmptyContraIndications() {
        assertEquals(0, contraIndications.getContraIndicatorScores());
    }

    @Test
    void shouldCalculateContraIndicatorScore() {
        addContraIndicators(TEST_CI1, BASE_TIME.minusSeconds(1));
        addContraIndicators(TEST_CI2, BASE_TIME.minusSeconds(2));
        assertEquals(7, contraIndications.getContraIndicatorScores());
    }

    @Test
    void shouldReturnEmptyOptionalForLatestContraIndicatorFromEmptyContraIndications() {
        assertFalse(contraIndications.getLatestContraIndicator().isPresent());
    }

    @Test
    void shouldIdentifyLatestContraIndicator() {
        addContraIndicators(TEST_CI1, BASE_TIME.minusSeconds(1));
        addContraIndicators(TEST_CI2, BASE_TIME.minusSeconds(2));
        addContraIndicators(TEST_CI3, BASE_TIME.plusSeconds(3));
        Optional<ContraIndicator> latestContraIndicator =
                contraIndications.getLatestContraIndicator();
        assertTrue(latestContraIndicator.isPresent());
        assertEquals(TEST_CI3, latestContraIndicator.get().getCode());
    }

    private void addContraIndicators(final String code, Instant issuanceDate) {
        ContraIndicator contraIndicator =
                ContraIndicator.builder().code(code).issuanceDate(issuanceDate).build();
        Map<String, ContraIndicator> updatedContraIndicators =
                new HashMap<>(contraIndications.getContraIndicators());
        updatedContraIndicators.put(code, contraIndicator);
        contraIndications =
                contraIndications.toBuilder().contraIndicators(updatedContraIndicators).build();
    }
}
