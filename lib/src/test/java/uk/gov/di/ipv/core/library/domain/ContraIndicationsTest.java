package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ContraIndicationsTest {
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
    private static final ContraIndications TEST_NO_CONTRAINDICATORS =
            ContraIndications.builder()
                    .contraIndicatorScoreMap(CONTRA_INDICATOR_SCORE_MAP)
                    .contraIndicatorMap(Map.of())
                    .build();
    private static final ContraIndications TEST_CONTRAINDICATORS =
            ContraIndications.builder()
                    .contraIndicatorScoreMap(CONTRA_INDICATOR_SCORE_MAP)
                    .contraIndicatorMap(
                            Map.of(
                                    TEST_CI1,
                                    ContraIndicator.builder()
                                            .contraIndicatorCode(TEST_CI1)
                                            .issuanceDate(BASE_TIME.minus(1, ChronoUnit.SECONDS))
                                            .build(),
                                    TEST_CI2,
                                    ContraIndicator.builder()
                                            .contraIndicatorCode(TEST_CI2)
                                            .issuanceDate(BASE_TIME.minus(2, ChronoUnit.SECONDS))
                                            .build()))
                    .build();

    @Test
    void shouldReturnZeroScoreForEmptyContraIndications() {
        assertEquals(0, TEST_NO_CONTRAINDICATORS.getContraIndicatorScore());
    }

    @Test
    void shouldCalculateContraIndicatorScore() {
        assertEquals(7, TEST_CONTRAINDICATORS.getContraIndicatorScore());
    }

    @Test
    void shouldReturnEmptyOptionalForLatestContraIndicatorFromEmptyContraIndications() {
        assertEquals(Optional.empty(), TEST_NO_CONTRAINDICATORS.getLatestContraIndicator());
    }

    @Test
    void shouldIdentifyLatestContraIndicator() {
        assertEquals(
                TEST_CONTRAINDICATORS.getContraIndicatorMap().get(TEST_CI1),
                TEST_CONTRAINDICATORS.getLatestContraIndicator().get());
    }
}
