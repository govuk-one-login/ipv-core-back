package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.exceptions.MitigationRouteConfigNotFoundException;
import uk.gov.di.ipv.core.library.journeyuris.JourneyUris;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.ALTERNATE_DOC_MITIGATION_ENABLED;

@ExtendWith(MockitoExtension.class)
class CiMitUtilityServiceTest {
    @Mock private ConfigService mockConfigService;

    @InjectMocks private CiMitUtilityService ciMitUtilityService;

    @ParameterizedTest
    @MethodSource("ciScoresAndSurpassedThresholds")
    void isBreachingCiThresholdShouldReturnTrueIfCiScoreBreaching(
            int ciScore1, int ciScore2, int ciScoreThreshold) {
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD))
                .thenReturn(String.valueOf(ciScoreThreshold));

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        Map<String, ContraIndicator> cisMap = new HashMap<>();
        cisMap.put("ci_1", ContraIndicator.builder().build());
        cisMap.put("ci_2", ContraIndicator.builder().build());

        ContraIndicators cis = ContraIndicators.builder().contraIndicatorsMap(cisMap).build();

        assertTrue(
                ciMitUtilityService.isBreachingCiThreshold(cis),
                String.format(
                        "CIs with scores %s and %s should breach threshold of %s",
                        ciScore1, ciScore2, ciScoreThreshold));
    }

    static Stream<Arguments> ciScoresAndSurpassedThresholds() {
        return Stream.of(
                Arguments.of(5, 5, 9),
                Arguments.of(3, 7, 2),
                Arguments.of(1, 7, 2),
                Arguments.of(101, 201, 301));
    }

    @ParameterizedTest
    @MethodSource("ciScoresAndUnsurpassedThresholds")
    void isBreachingCiThresholdShouldReturnFalseIfCiScoreNotBreaching(
            int ciScore1, int ciScore2, int ciScoreThreshold) {
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD))
                .thenReturn(String.valueOf(ciScoreThreshold));

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        Map<String, ContraIndicator> cisMap = new HashMap<>();
        cisMap.put("ci_1", ContraIndicator.builder().build());
        cisMap.put("ci_2", ContraIndicator.builder().build());

        ContraIndicators cis = ContraIndicators.builder().contraIndicatorsMap(cisMap).build();

        assertFalse(
                ciMitUtilityService.isBreachingCiThreshold(cis),
                String.format(
                        "CIs with scores %s and %s shouldn't be breach threshold of %s",
                        ciScore1, ciScore2, ciScoreThreshold));
    }

    static Stream<Arguments> ciScoresAndUnsurpassedThresholds() {
        return Stream.of(
                Arguments.of(5, 4, 9),
                Arguments.of(3, 7, 12),
                Arguments.of(1, 7, 20),
                Arguments.of(101, 201, 350));
    }

    @Test
    void isBreachingCiThresholdIfMitigatedShouldReturnTrueWhenScoreExceedsThreshold() {
        ContraIndicator ci1 =
                ContraIndicator.builder().code("ciCode1").issuanceDate("some_date").build();
        ContraIndicator ci2 =
                ContraIndicator.builder().code("ciCode2").issuanceDate("some_date").build();
        ContraIndicators cis =
                ContraIndicators.builder()
                        .contraIndicatorsMap(Map.of("ciCode1", ci1, "ciCode2", ci2))
                        .build();
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 4, -3, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 9, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("9");

        assertTrue(ciMitUtilityService.isBreachingCiThresholdIfMitigated(ci1, cis));
        assertFalse(ciMitUtilityService.isBreachingCiThresholdIfMitigated(ci2, cis));
    }

    @Test
    void isBreachingCiThresholdIfMitigatedShouldReturnFalseWhenScoreEqualsThreshold() {
        ContraIndicator ci1 =
                ContraIndicator.builder().code("ciCode1").issuanceDate("some_date").build();
        ContraIndicator ci2 =
                ContraIndicator.builder().code("ciCode2").issuanceDate("some_date").build();
        ContraIndicators cis =
                ContraIndicators.builder()
                        .contraIndicatorsMap(Map.of("ciCode1", ci1, "ciCode2", ci2))
                        .build();
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 5, -5, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 5, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");

        assertFalse(ciMitUtilityService.isBreachingCiThresholdIfMitigated(ci1, cis));
    }

    @Test
    void getMitigationJourneyResponseShouldReturnMitigationWhenCiCanBeMitigated() throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String document = "doc_type/213123";
        String documentType = "doc_type";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .document(document)
                        .issuanceDate("some_date")
                        .build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");

        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.of(new JourneyResponse(journey)), result);
    }

    @Test
    void getMitigationJourneyResponseShouldReturnMitigationWhenCiCanBeMitigatedWithNoDocInCi()
            throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, null))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");

        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.of(new JourneyResponse(journey)), result);
    }

    @Test
    void
            getMitigationJourneyResponseShouldThrowWhenCiCanBeMitigatedWithNonExistingMitigationRouteForDocumentType()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String document = "nondoc_type/213123";
        String documentType = "doc_type";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .document(document)
                        .issuanceDate("some_date")
                        .build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");

        // assert
        assertThrows(
                MitigationRouteConfigNotFoundException.class,
                () -> ciMitUtilityService.getCiMitigationJourneyStep(cis));
    }

    @Test
    void getMitigationJourneyResponseShouldReturnEmptyWhenCiIsNotMitigatable() throws Exception {
        // arrange
        var code = "ci_code";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig()).thenReturn(Collections.emptyMap());

        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void getMitigationJourneyResponseShouldReturnEmptyWhenCiIsAlreadyMitigated() throws Exception {
        // arrange
        var code = "ci_code";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .issuanceDate("some_date")
                        .mitigation(List.of(Mitigation.builder().build()))
                        .build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute("journey", null))));

        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void getMitigationJourneyResponseShouldReturnEmptyWhenMitigationDoesNotResolveBreach()
            throws Exception {
        // arrange
        var code = "ci_code";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute("journey", null))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -1, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");

        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void getMitigationJourneyResponseShouldThrowWhenCiMitigationJourneyConfigNotFoundForDocType()
            throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, "documentType"))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");

        // assert
        assertThrows(
                MitigationRouteConfigNotFoundException.class,
                () -> ciMitUtilityService.getCiMitigationJourneyStep(cis));
    }

    @Test
    void getMitigationJourneyResponseShouldReturnEmptyWhenCiCanBeMitigatedWithDisableMitigation()
            throws Exception {
        // arrange
        var code = "ci_code";
        var journey = JourneyUris.JOURNEY_ALTERNATE_DOC_INVALID_DL_PATH;
        String document = "doc_type/213123";
        String documentType = "doc_type";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .document(document)
                        .issuanceDate("some_date")
                        .build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");
        when(mockConfigService.enabled(ALTERNATE_DOC_MITIGATION_ENABLED)).thenReturn(false);
        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void
            getMitigationJourneyResponseShouldReturnMitigationWhenCiCanBeMitigatedWithEnableMitigation()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var journey = JourneyUris.JOURNEY_ALTERNATE_DOC_INVALID_DL_PATH;
        String document = "doc_type/213123";
        String documentType = "doc_type";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .document(document)
                        .issuanceDate("some_date")
                        .build();
        var cis = ContraIndicators.builder().contraIndicatorsMap(Map.of(code, ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");
        when(mockConfigService.enabled(ALTERNATE_DOC_MITIGATION_ENABLED)).thenReturn(true);
        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.of(new JourneyResponse(journey)), result);
    }

    @Test
    void
            getCiMitigationJourneyStepShouldReturnEmptyWhenCiCanBeMitigatedButHasAlreadyMitigatedContraIndicator()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String document = "doc_type/213123";
        String documentType = "doc_type";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .document(document)
                        .issuanceDate("some_date")
                        .build();
        var mitCi =
                ContraIndicator.builder()
                        .code("mit_ci_code")
                        .document(document)
                        .issuanceDate("some_date")
                        .mitigation(List.of(Mitigation.builder().build()))
                        .build();
        var cis =
                ContraIndicators.builder()
                        .contraIndicatorsMap(Map.of(code, ci, "mit_ci_code", mitCi))
                        .build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        code,
                        new ContraIndicatorConfig(code, 7, -5, "X"),
                        "mit_ci_code",
                        new ContraIndicatorConfig("mit_ci_code", 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("5");

        // act
        var result = ciMitUtilityService.getCiMitigationJourneyStep(cis);

        // assert
        assertEquals(Optional.empty(), result);
    }
}
