package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContraIndicatorsTest {
    private ContraIndicators contraIndicators;
    private static final String TEST_CI1 = "CI1";
    private static final String TEST_CI2 = "CI2";
    private static final String TEST_CI3 = "CI3";

    private static final String TEST_CI4_UNKNOWN = "CI4";
    private static final Instant BASE_TIME = Instant.now();
    private static final Map<String, ContraIndicatorConfig> CONTRA_INDICATOR_CONFIG_MAP =
            Map.of(
                    TEST_CI1,
                    new ContraIndicatorConfig(TEST_CI1, 4, -3, "1", "1"),
                    TEST_CI2,
                    new ContraIndicatorConfig(TEST_CI2, 3, -3, "2", "2"),
                    TEST_CI3,
                    new ContraIndicatorConfig(TEST_CI3, 2, -1, "3", "3"));

    @BeforeEach
    void setup() {
        contraIndicators = ContraIndicators.builder().contraIndicatorsMap(Map.of()).build();
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoContraIndicatorExistInContraIndications() {
        assertFalse(contraIndicators.getLatestContraIndicator().isPresent());
    }

    @Test
    void shouldReturnZeroScoreWhenNoContraIndicatorExistInContraIndications()
            throws UnrecognisedCiException {
        assertEquals(0, contraIndicators.getContraIndicatorScore(CONTRA_INDICATOR_CONFIG_MAP));
    }

    @Test
    void shouldCalculateContraIndicatorScoreIncludeMitigation() throws UnrecognisedCiException {
        addContraIndicators(
                TEST_CI1, BASE_TIME.minusSeconds(1), List.of(Mitigation.builder().build()));
        addContraIndicators(
                TEST_CI2, BASE_TIME.minusSeconds(2), List.of(Mitigation.builder().build()));
        assertEquals(1, contraIndicators.getContraIndicatorScore(CONTRA_INDICATOR_CONFIG_MAP));
    }

    @Test
    void shouldCalculateContraIndicatorScoreIncludeMitigationAndSomeEmptyMitigations()
            throws UnrecognisedCiException {
        addContraIndicators(
                TEST_CI1, BASE_TIME.minusSeconds(1), List.of(Mitigation.builder().build()));
        addContraIndicators(TEST_CI2, BASE_TIME.minusSeconds(2), Collections.emptyList());
        addContraIndicators(TEST_CI3, BASE_TIME.minusSeconds(4), null);
        assertEquals(6, contraIndicators.getContraIndicatorScore(CONTRA_INDICATOR_CONFIG_MAP));
    }

    @Test
    void shouldFindLatestContraIndicator() {
        addContraIndicators(TEST_CI1, BASE_TIME.minusSeconds(1), null);
        addContraIndicators(TEST_CI2, BASE_TIME.minusSeconds(2), Collections.emptyList());
        addContraIndicators(TEST_CI3, BASE_TIME.plusSeconds(3), null);
        Optional<ContraIndicator> latestContraIndicator =
                contraIndicators.getLatestContraIndicator();
        assertTrue(latestContraIndicator.isPresent());
        assertEquals(TEST_CI3, latestContraIndicator.get().getCode());
    }

    @Test
    void shouldFindLatestContraIndicatorWhenMultipleIndicatorsAtSameTime() {
        addContraIndicators(TEST_CI1, BASE_TIME, null);
        addContraIndicators(TEST_CI2, BASE_TIME, null);
        addContraIndicators(TEST_CI3, BASE_TIME.minusSeconds(3), null);
        Optional<ContraIndicator> latestContraIndicator =
                contraIndicators.getLatestContraIndicator();
        assertTrue(latestContraIndicator.isPresent());
        assertEquals(TEST_CI2, latestContraIndicator.get().getCode());
    }

    @Test
    void shouldRaiseExceptionIfScoringUnrecognisedContraIndicator() {
        addContraIndicators(
                TEST_CI1, BASE_TIME.minusSeconds(1), List.of(Mitigation.builder().build()));
        addContraIndicators(
                TEST_CI4_UNKNOWN, BASE_TIME.minusSeconds(2), List.of(Mitigation.builder().build()));
        assertThrows(
                UnrecognisedCiException.class,
                () -> contraIndicators.getContraIndicatorScore(CONTRA_INDICATOR_CONFIG_MAP));
    }

    @Test
    void hasMitigationsShouldReturnTrueIfMitigationsExist() {
        addContraIndicators(TEST_CI1, BASE_TIME, null);
        addContraIndicators(TEST_CI2, BASE_TIME, null);
        addContraIndicators(TEST_CI3, BASE_TIME, List.of(Mitigation.builder().build()));
        assertTrue(contraIndicators.hasMitigations());
    }

    @Test
    void hasMitigationsShouldReturnFalseIfNoMitigationsExist() {
        addContraIndicators(TEST_CI1, BASE_TIME, null);
        addContraIndicators(TEST_CI2, BASE_TIME, null);
        addContraIndicators(TEST_CI3, BASE_TIME, null);
        assertFalse(contraIndicators.hasMitigations());
    }

    private void addContraIndicators(
            final String code, Instant issuanceDate, List<Mitigation> mitigations) {
        ContraIndicator contraIndicator =
                ContraIndicator.builder()
                        .code(code)
                        .issuanceDate(issuanceDate.toString())
                        .mitigation(mitigations)
                        .build();
        Map<String, ContraIndicator> updatedContraIndicators =
                new HashMap<>(contraIndicators.getContraIndicatorsMap());
        updatedContraIndicators.put(code, contraIndicator);
        contraIndicators =
                contraIndicators.toBuilder().contraIndicatorsMap(updatedContraIndicators).build();
    }
}
