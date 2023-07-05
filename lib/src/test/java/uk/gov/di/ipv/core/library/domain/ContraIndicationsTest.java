package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
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
        contraIndications = ContraIndications.builder().contraIndicators(Map.of()).build();
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoContraIndicatorExistInContraIndications() {
        assertFalse(contraIndications.getLatestContraIndicator().isPresent());
    }

    @Test
    void shouldReturnZeroScoreWhenNoContraIndicatorExistInContraIndications() {
        assertEquals(
                0, contraIndications.getContraIndicatorScore(CONTRA_INDICATOR_SCORE_MAP, false));
    }

    @Test
    void shouldCalculateContraIndicatorScoreExcludeMitigation() {
        addContraIndicators(
                TEST_CI1, BASE_TIME.minusSeconds(1), List.of(Mitigation.builder().build()));
        addContraIndicators(
                TEST_CI2, BASE_TIME.minusSeconds(2), List.of(Mitigation.builder().build()));
        assertEquals(
                7, contraIndications.getContraIndicatorScore(CONTRA_INDICATOR_SCORE_MAP, false));
        contraIndications = ContraIndications.builder().contraIndicators(Map.of()).build();
    }

    @Test
    void shouldCalculateContraIndicatorScoreIncludeMitigation() {
        addContraIndicators(
                TEST_CI1, BASE_TIME.minusSeconds(1), List.of(Mitigation.builder().build()));
        addContraIndicators(
                TEST_CI2, BASE_TIME.minusSeconds(2), List.of(Mitigation.builder().build()));
        assertEquals(
                1, contraIndications.getContraIndicatorScore(CONTRA_INDICATOR_SCORE_MAP, true));
        contraIndications = ContraIndications.builder().contraIndicators(Map.of()).build();
    }

    @Test
    void shouldCalculateContraIndicatorScoreIncludeMitigationAndSomeEmptyMitigations() {
        addContraIndicators(
                TEST_CI1, BASE_TIME.minusSeconds(1), List.of(Mitigation.builder().build()));
        addContraIndicators(TEST_CI2, BASE_TIME.minusSeconds(2), null);
        addContraIndicators(TEST_CI3, BASE_TIME.minusSeconds(4), null);
        assertEquals(
                6, contraIndications.getContraIndicatorScore(CONTRA_INDICATOR_SCORE_MAP, true));
        contraIndications = ContraIndications.builder().contraIndicators(Map.of()).build();
    }

    @Test
    void shouldFindLatestContraIndicator() {
        addContraIndicators(TEST_CI1, BASE_TIME.minusSeconds(1), null);
        addContraIndicators(TEST_CI2, BASE_TIME.minusSeconds(2), null);
        addContraIndicators(TEST_CI3, BASE_TIME.plusSeconds(3), null);
        Optional<ContraIndicator> latestContraIndicator =
                contraIndications.getLatestContraIndicator();
        assertTrue(latestContraIndicator.isPresent());
        assertEquals(TEST_CI3, latestContraIndicator.get().getCode());
    }

    @Test
    void shouldFindLatestContraIndicatorWhenMultipleIndicatorsAtSameTime() {
        addContraIndicators(TEST_CI1, BASE_TIME, null);
        addContraIndicators(TEST_CI2, BASE_TIME, null);
        addContraIndicators(TEST_CI3, BASE_TIME.minusSeconds(3), null);
        Optional<ContraIndicator> latestContraIndicator =
                contraIndications.getLatestContraIndicator();
        assertTrue(latestContraIndicator.isPresent());
        assertEquals(TEST_CI2, latestContraIndicator.get().getCode());
    }

    private void addContraIndicators(
            final String code, Instant issuanceDate, List<Mitigation> mitigations) {
        ContraIndicator contraIndicator =
                ContraIndicator.builder()
                        .code(code)
                        .issuanceDate(issuanceDate)
                        .mitigations(mitigations)
                        .build();
        Map<String, ContraIndicator> updatedContraIndicators =
                new HashMap<>(contraIndications.getContraIndicators());
        updatedContraIndicators.put(code, contraIndicator);
        contraIndications =
                contraIndications.toBuilder().contraIndicators(updatedContraIndicators).build();
    }
}
