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
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;

@ExtendWith(MockitoExtension.class)
class CiMitUtilityServiceTest {
    private static final Vot TEST_VOT = Vot.P2;
    @Mock private ConfigService mockConfigService;

    @InjectMocks private CiMitUtilityService ciMitUtilityService;

    @ParameterizedTest
    @MethodSource("ciScoresAndSurpassedThresholds")
    void isBreachingCiThreshold_ShouldReturnTrue_IfCiScoreBreaching(
            int ciScore1, int ciScore2, int ciScoreThreshold) {
        // Arrange
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn(String.valueOf(ciScoreThreshold));

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var usersCis =
                List.of(
                        ContraIndicator.builder().code("ci_1").build(),
                        ContraIndicator.builder().code("ci_2").build());
        ContraIndicators cis = ContraIndicators.builder().usersContraIndicators(usersCis).build();

        // Act
        var result = ciMitUtilityService.isBreachingCiThreshold(cis, TEST_VOT);

        // Assert
        assertTrue(
                result,
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
    void isBreachingCiThreshold_ShouldReturnFalse_IfCiScoreNotBreaching(
            int ciScore1, int ciScore2, int ciScoreThreshold) {
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn(String.valueOf(ciScoreThreshold));

        // Arrange
        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var usersCis =
                List.of(
                        ContraIndicator.builder().code("ci_1").build(),
                        ContraIndicator.builder().code("ci_2").build());
        ContraIndicators cis = ContraIndicators.builder().usersContraIndicators(usersCis).build();

        // Act
        var result = ciMitUtilityService.isBreachingCiThreshold(cis, TEST_VOT);

        // Assert
        assertFalse(
                result,
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
    void isBreachingCiThresholdIfMitigated_ShouldReturnTrue_WhenScoreExceedsThreshold() {
        // Arrange
        ContraIndicator ci1 =
                ContraIndicator.builder().code("ciCode1").issuanceDate("some_date").build();
        ContraIndicator ci2 =
                ContraIndicator.builder().code("ciCode2").issuanceDate("some_date").build();
        ContraIndicators cis =
                ContraIndicators.builder().usersContraIndicators(List.of(ci1, ci2)).build();
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 4, -3, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 9, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("9");

        // Act
        boolean result = ciMitUtilityService.isBreachingCiThresholdIfMitigated(ci1, cis, TEST_VOT);

        // Assert
        assertTrue(result);
    }

    @Test
    void isBreachingCiThresholdIfMitigated_ShouldReturnFalse_WhenScoreIsBelowThreshold() {
        // Arrange
        ContraIndicator ci1 =
                ContraIndicator.builder().code("ciCode1").issuanceDate("some_date").build();
        ContraIndicator ci2 =
                ContraIndicator.builder().code("ciCode2").issuanceDate("some_date").build();
        ContraIndicators cis =
                ContraIndicators.builder().usersContraIndicators(List.of(ci1, ci2)).build();
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 4, -3, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 9, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("9");

        // Act
        boolean result = ciMitUtilityService.isBreachingCiThresholdIfMitigated(ci2, cis, TEST_VOT);

        // Assert
        assertFalse(result);
    }

    @Test
    void isBreachingCiThresholdIfMitigated_ShouldReturnFalse_WhenScoreEqualsThreshold() {
        ContraIndicator ci1 =
                ContraIndicator.builder().code("ciCode1").issuanceDate("some_date").build();
        ContraIndicator ci2 =
                ContraIndicator.builder().code("ciCode2").issuanceDate("some_date").build();
        ContraIndicators cis =
                ContraIndicators.builder().usersContraIndicators(List.of(ci1, ci2)).build();
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 5, -5, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 5, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // Act
        boolean result = ciMitUtilityService.isBreachingCiThresholdIfMitigated(ci1, cis, TEST_VOT);

        // Assert
        assertFalse(result);
    }

    @ParameterizedTest
    @MethodSource("ciScoresAndUnsurpassedThresholds")
    void getMitigationJourneyIfBreaching_ShouldReturnEmpty_IfCiScoreNotBreaching(
            int ciScore1, int ciScore2, int ciScoreThreshold) throws ConfigException {
        // Arrange
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, "P2"))
                .thenReturn(String.valueOf(ciScoreThreshold));

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var usersCis =
                List.of(
                        ContraIndicator.builder().code("ci_1").build(),
                        ContraIndicator.builder().code("ci_2").build());
        ContraIndicators cis = ContraIndicators.builder().usersContraIndicators(usersCis).build();

        // Act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // Assert
        assertTrue(
                result.isEmpty(),
                String.format(
                        "CIs with scores %s and %s should not breach threshold of %s",
                        ciScore1, ciScore2, ciScoreThreshold));
    }

    @Test
    void getMitigationJourneyIfBreaching_ShouldReturnMitigation_WhenCiCanBeMitigated()
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
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of(new JourneyResponse(journey)), result);
    }

    @Test
    void getMitigationJourneyIfBreaching_ShouldReturnMitigation_WhenCiCanBeMitigatedWithNoDocInCi()
            throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, null))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of(new JourneyResponse(journey)), result);
    }

    @Test
    void
            getMitigationJourneyIfBreaching_ShouldReturnFailWithCi_IfCiIsMitigatableButDocTypeIsNotConfigured()
                    throws Exception {
        // Arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String ciDocumentIdentifier = "a-not-configured-doc-type";
        String configuredDocumentIdentifier = "a-configured-doc-type";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .document(ciDocumentIdentifier)
                        .issuanceDate("some_date")
                        .build();
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(
                        Map.of(
                                code,
                                List.of(
                                        new MitigationRoute(
                                                journey, configuredDocumentIdentifier))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // Act
        Optional<JourneyResponse> result =
                ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // Assert
        assertEquals(Optional.of(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH)), result);
    }

    @Test
    void getMitigationJourneyIfBreaching_ShouldReturnFailWithCi_WhenCiIsNotMitigatable()
            throws Exception {
        // arrange
        var code = "ci_code";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci)).build();
        when(mockConfigService.getCimitConfig()).thenReturn(Collections.emptyMap());
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH)), result);
    }

    @Test
    void getMitigationJourneyIfBreaching_ShouldReturnEmpty_WhenCiIsAlreadyMitigated()
            throws Exception {
        // arrange
        var code = "ci_code";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .issuanceDate("some_date")
                        .mitigation(List.of(Mitigation.builder().build()))
                        .build();
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci)).build();
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void getMitigationJourneyIfBreaching_ShouldReturnFailWithCi_WhenMitigationDoesNotResolveBreach()
            throws Exception {
        // arrange
        var code = "ci_code";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute("journey", null))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -1, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH)), result);
    }

    @Test
    void
            getCiMitigationJourneyResponse_ShouldReturnFailWithCi_WhenCiMitigationJourneyConfigNotFoundForDocType()
                    throws Exception {
        // Arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, "documentType"))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // Act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // Assert
        assertEquals(Optional.of(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH)), result);
    }

    @Test
    void
            getMitigationJourneyIfBreaching_ShouldReturnFailWithCi_WhenCiCanBeMitigatedButHasAlreadyMitigatedContraIndicator()
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
        var cis = ContraIndicators.builder().usersContraIndicators(List.of(ci, mitCi)).build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        code,
                        new ContraIndicatorConfig(code, 7, -5, "X"),
                        "mit_ci_code",
                        new ContraIndicatorConfig("mit_ci_code", 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn("5");

        // act
        var result = ciMitUtilityService.getMitigationJourneyIfBreaching(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH)), result);
    }

    @Test
    void getMitigatedCiJourneyResponse_ShouldReturnMitigation_WhenCiCanBeMitigated()
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
                        .mitigation(List.of(Mitigation.builder().build()))
                        .build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));

        // act
        var result = ciMitUtilityService.getMitigatedCiJourneyResponse(ci);

        // assert
        assertEquals(Optional.of(new JourneyResponse(journey)), result);
    }

    @Test
    void getMitigatedCiJourneyResponse_ShouldReturnEmpty_WhenCiIsNotMitigatable() throws Exception {
        // arrange
        var code = "ci_code";
        var ci = ContraIndicator.builder().code(code).issuanceDate("some_date").build();
        when(mockConfigService.getCimitConfig()).thenReturn(Collections.emptyMap());

        // act
        var result = ciMitUtilityService.getMitigatedCiJourneyResponse(ci);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void getMitigatedCiJourneyResponse_ShouldReturnEmptyOptional_IfMitigationRouteNotFound()
            throws Exception {
        // Arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String document = "not-configured-doc-type/213123";
        String documentType = "doc_type";
        var ci =
                ContraIndicator.builder()
                        .code(code)
                        .document(document)
                        .issuanceDate("some_date")
                        .mitigation(List.of(Mitigation.builder().build()))
                        .build();
        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));

        // Act
        var result = ciMitUtilityService.getMitigatedCiJourneyResponse(ci);

        // Assert
        assertTrue(result.isEmpty());
    }
}
