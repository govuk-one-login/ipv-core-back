package uk.gov.di.ipv.core.library.domain.cimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorMitigation;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MITIGATION_ENABLED;

@ExtendWith(MockitoExtension.class)
class CimitEvaluatorTest {

    private static final String TEST_USER_ID = "test-user-id";
    private static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH);
    private static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_KBV_FAIL =
            new JourneyResponse(JOURNEY_PYI_KBV_FAIL);
    private static final String JOURNEY_PYI_CI3_FAIL_SEPARATE_SESSION =
            "/journey/pyi-ci3-fail-separate-session";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_CI3_FAIL_SEPARATE_SESSION =
            new JourneyResponse(JOURNEY_PYI_CI3_FAIL_SEPARATE_SESSION);
    private static final String JOURNEY_PYI_CI3_FAIL_SAME_SESSION =
            "/journey/pyi-ci3-fail-same-session";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_CI3_FAIL_SAME_SESSION =
            new JourneyResponse(JOURNEY_PYI_CI3_FAIL_SAME_SESSION);
    @Mock ConfigService mockConfigService;
    @InjectMocks CimitEvaluator evaluator;

    private static final String CI1 = "X98";
    private static final String CI2 = "X99";
    private static final String CI3 = "X97";
    private static final Map<String, ContraIndicatorScore> TEST_CI_SCORES =
            Map.of(
                    CI1,
                    new ContraIndicatorScore(CI1, 1, -1, null, Collections.emptyList()),
                    CI2,
                    new ContraIndicatorScore(CI2, 3, -2, null, Collections.emptyList()),
                    CI3,
                    new ContraIndicatorScore(CI3, 4, -3, null, Collections.emptyList()));

    private static final Map<String, ContraIndicatorMitigation> TEST_CI_MITIGATION_CONFIG =
            Map.of(
                    CI3,
                    ContraIndicatorMitigation.builder()
                            .sameSessionStep(JOURNEY_PYI_CI3_FAIL_SAME_SESSION)
                            .separateSessionStep(JOURNEY_PYI_CI3_FAIL_SEPARATE_SESSION)
                            .build());

    @Test
    void getJourneyResponseForStoredCisShouldReturnEmptyOptionalIfNoCis() throws Exception {
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("3");

        assertTrue(evaluator.getJourneyResponseForStoredCis(List.of()).isEmpty());
    }

    @Test
    void getJourneyResponseForStoredCisShouldReturnEmptyOptionalIfCiScoreLessThanThreshold()
            throws Exception {
        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "Y03#hash",
                        "issuer",
                        "2022-09-21T07:57:14.332Z",
                        CI2,
                        "123456789",
                        null);
        setupMockContraIndicatorScoringConfig();

        assertTrue(
                evaluator.getJourneyResponseForStoredCis(List.of(contraIndicatorItem)).isEmpty());
    }

    @Test
    void
            getJourneyResponseForStoredCisShouldReturnKbvFailIfCiScoreGreaterThanThresholdAndLastStoredCiWasIssuedByKbv()
                    throws Exception {
        ContraIndicatorItem otherCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X98#hash",
                        "otherIssuer",
                        "2022-09-21T08:00:00.000Z",
                        CI1,
                        "123456789",
                        null);
        ContraIndicatorItem kbvCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X99#hash",
                        "kbvIssuer",
                        "2022-09-21T08:01:00.000Z",
                        CI2,
                        "123456789",
                        null);

        setupMockContraIndicatorScoringConfig();
        when(mockConfigService.getComponentId("kbv")).thenReturn("kbvIssuer");

        assertEquals(
                Optional.of(JOURNEY_RESPONSE_PYI_KBV_FAIL),
                evaluator.getJourneyResponseForStoredCis(List.of(otherCiItem, kbvCiItem)));
    }

    @Test
    void
            getJourneyResponseForStoredCisShouldReturnNoMatchIfCiScoreGreaterThanThresholdAndLastStoredCiWasNotIssuedByKbv()
                    throws Exception {
        ContraIndicatorItem otherCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X98#hash",
                        "otherIssuer",
                        "2022-09-21T08:01:00.000Z",
                        CI1,
                        "123456789",
                        null);
        ContraIndicatorItem kbvCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X99#hash",
                        "kbvIssuer",
                        "2022-09-21T08:00:00.000Z",
                        CI2,
                        "123456789",
                        null);

        setupMockContraIndicatorScoringConfig();

        assertEquals(
                Optional.of(JOURNEY_RESPONSE_PYI_NO_MATCH),
                evaluator.getJourneyResponseForStoredCis(List.of(otherCiItem, kbvCiItem)));
    }

    @Test
    void getJourneyResponseForStoredCisShouldThrowIfUnrecognisedCi() {
        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "Y03#hash",
                        "issuer",
                        "2022-09-21T07:57:14.332Z",
                        "Y03",
                        "123456789",
                        null);

        when(mockConfigService.getContraIndicatorScoresMap()).thenReturn(TEST_CI_SCORES);

        assertThrows(
                UnrecognisedCiException.class,
                () -> evaluator.getJourneyResponseForStoredCis(List.of(contraIndicatorItem)));
    }

    private void setupMockContraIndicatorScoringConfig() {
        when(mockConfigService.getContraIndicatorScoresMap()).thenReturn(TEST_CI_SCORES);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("3");
    }

    private void setupMockContraIndicatorTreatmentConfig() throws ConfigException {
        when(mockConfigService.getCiMitConfig()).thenReturn(TEST_CI_MITIGATION_CONFIG);
    }

    private void setupMockMitigationEnabledFeatureFlag(boolean mitigationEnabled) {
        when(mockConfigService.enabled(MITIGATION_ENABLED)).thenReturn(mitigationEnabled);
    }

    @Nested
    @DisplayName("getJourneyResponseForStoredContraIndicators tests")
    class ContraIndicatorJourneySelectionTests {
        class TestContraIndicator {
            private String code;
            private List<String> mitigations;

            TestContraIndicator(String code, List<String> mitigations) {
                this.code = code;
                this.mitigations = mitigations;
            }

            TestContraIndicator(String code) {
                this(code, List.of());
            }
        }

        private ContraIndicators buildTestContraIndications(
                TestContraIndicator... testContraIndicators) {
            return ContraIndicators.builder()
                    .contraIndicatorsMap(
                            Arrays.stream(testContraIndicators)
                                    .collect(
                                            Collectors.toMap(
                                                    testContraIndicator -> testContraIndicator.code,
                                                    this::buildTestContraIndicator)))
                    .build();
        }

        private ContraIndicator buildTestContraIndicator(TestContraIndicator testContraIndicator) {
            return ContraIndicator.builder()
                    .code(testContraIndicator.code)
                    .issuanceDate(Instant.now().toString())
                    .mitigation(buildTestMitigations(testContraIndicator.mitigations))
                    .build();
        }

        private List<Mitigation> buildTestMitigations(List<String> mitigations) {
            return mitigations.stream()
                    .map(mitigation -> Mitigation.builder().code(mitigation).build())
                    .collect(Collectors.toList());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void shouldNotReturnJourneyIfNoContraIndicators(boolean mitigationEnabled)
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications = buildTestContraIndications();
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertTrue(journeyResponse.isEmpty());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void shouldNotReturnJourneyIfContraIndicatorsDoNotBreachThreshold(boolean mitigationEnabled)
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(new TestContraIndicator(CI2));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertTrue(journeyResponse.isEmpty());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void
                shouldReturnPyiNoMatchJourneyIfContraIndicatorsBreachThresholdAndNoConfigForLatestContraIndicator(
                        boolean mitigationEnabled) throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI3), new TestContraIndicator(CI1));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            setupMockContraIndicatorTreatmentConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertEquals(JOURNEY_RESPONSE_PYI_NO_MATCH, journeyResponse.get());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void
                shouldReturnCustomSeparateSessionJourneyIfContraIndicatorsBreachThresholdAndConfigForLatestContraIndicator(
                        boolean mitigationEnabled) throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1), new TestContraIndicator(CI3));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            setupMockContraIndicatorTreatmentConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, true);
            assertEquals(JOURNEY_RESPONSE_PYI_CI3_FAIL_SEPARATE_SESSION, journeyResponse.get());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void
                shouldReturnCustomSameSessionJourneyIfContraIndicatorsBreachThresholdAndConfigForLatestContraIndicator(
                        boolean mitigationEnabled) throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1), new TestContraIndicator(CI3));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            setupMockContraIndicatorTreatmentConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertEquals(JOURNEY_RESPONSE_PYI_CI3_FAIL_SAME_SESSION, journeyResponse.get());
        }

        @Test
        void shouldNotReturnJourneyIfMitigationEnabledAndSufficientMitigation()
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1),
                            new TestContraIndicator(CI3, List.of("mitigated")));
            setupMockMitigationEnabledFeatureFlag(true);
            setupMockContraIndicatorScoringConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertTrue(journeyResponse.isEmpty());
        }
    }
}
