package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.Mitigation;

import java.sql.Date;
import java.time.Instant;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CIMIT_VC_NO_CI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_RESIDENCE_PERMIT_DCMAW;

@ExtendWith(MockitoExtension.class)
class CimitUtilityServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_USER_ID = "a-user-id";
    private static final Vot TEST_VOT = Vot.P2;
    private static final String TEST_CI1 = "CI1";
    private static final String TEST_CI2 = "CI2";
    private static final String TEST_CI3 = "CI3";
    private static final Instant BASE_TIME = Instant.now();
    private static final Map<String, ContraIndicatorConfig> CONTRA_INDICATOR_CONFIG_MAP =
            Map.of(
                    TEST_CI1,
                    new ContraIndicatorConfig(TEST_CI1, 4, -3, "1"),
                    TEST_CI2,
                    new ContraIndicatorConfig(TEST_CI2, 3, -3, "2"),
                    TEST_CI3,
                    new ContraIndicatorConfig(TEST_CI3, 2, -1, "3"));

    @Mock private ConfigService mockConfigService;

    @InjectMocks private CimitUtilityService cimitUtilityService;

    @BeforeEach
    void setup() {
        lenient()
                .when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(CONTRA_INDICATOR_CONFIG_MAP);
    }

    @ParameterizedTest
    @MethodSource("cisAndScores")
    void getContraIndicatorScoreShouldReturnCorrectScore(
            List<ContraIndicator> cis, int expectedScore) throws UnrecognisedCiException {
        assertEquals(expectedScore, cimitUtilityService.getContraIndicatorScore(cis));
    }

    static Stream<Arguments> cisAndScores() {
        return Stream.of(
                Arguments.of(List.of(), 0),
                Arguments.of(
                        List.of(
                                createCi(
                                        TEST_CI1,
                                        BASE_TIME.minusSeconds(1),
                                        List.of(new Mitigation()),
                                        "passport"),
                                createCi(
                                        TEST_CI1,
                                        BASE_TIME.minusSeconds(3),
                                        List.of(),
                                        "drivingLicence"),
                                createCi(
                                        TEST_CI2,
                                        BASE_TIME.minusSeconds(2),
                                        List.of(new Mitigation()),
                                        null)),
                        5),
                Arguments.of(
                        List.of(
                                createCi(
                                        TEST_CI1,
                                        BASE_TIME.minusSeconds(1),
                                        List.of(new Mitigation()),
                                        null),
                                createCi(
                                        TEST_CI2,
                                        BASE_TIME.minusSeconds(2),
                                        Collections.emptyList(),
                                        null),
                                createCi(TEST_CI3, BASE_TIME.minusSeconds(4), null, null)),
                        6));
    }

    @Test
    void shouldRaiseExceptionIfScoringUnrecognisedContraIndicator() {
        var cis =
                List.of(
                        createCi(
                                TEST_CI1,
                                BASE_TIME.minusSeconds(1),
                                List.of(new Mitigation()),
                                null),
                        createCi(
                                "unknown",
                                BASE_TIME.minusSeconds(2),
                                List.of(new Mitigation()),
                                null));

        assertThrows(
                UnrecognisedCiException.class,
                () -> cimitUtilityService.getContraIndicatorScore(cis));
    }

    @ParameterizedTest
    @MethodSource("ciScoresAndSurpassedThresholds")
    void isBreachingCiThreshold_ShouldReturnTrue_IfCiScoreBreaching(
            int ciScore1, int ciScore2, int ciScoreThreshold) {
        // Arrange
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn(String.valueOf(ciScoreThreshold));

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var cis = List.of(createCi("ci_1"), createCi("ci_2"));

        // Act
        var result = cimitUtilityService.isBreachingCiThreshold(cis, TEST_VOT);

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
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name()))
                .thenReturn(String.valueOf(ciScoreThreshold));

        // Arrange
        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var cis = List.of(createCi("ci_1"), createCi("ci_2"));

        // Act
        var result = cimitUtilityService.isBreachingCiThreshold(cis, TEST_VOT);

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
        var ci1 = createCi("ciCode1");
        var ci2 = createCi("ciCode2");
        var cis = List.of(ci1, ci2);

        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 4, -3, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 9, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("9");

        // Act
        boolean result = cimitUtilityService.isBreachingCiThresholdIfMitigated(ci1, cis, TEST_VOT);

        // Assert
        assertTrue(result);
    }

    @Test
    void isBreachingCiThresholdIfMitigated_ShouldReturnFalse_WhenScoreIsBelowThreshold() {
        // Arrange
        var ci1 = createCi("ciCode1");
        var ci2 = createCi("ciCode2");
        var cis = List.of(ci1, ci2);

        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 4, -3, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 9, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("9");

        // Act
        boolean result = cimitUtilityService.isBreachingCiThresholdIfMitigated(ci2, cis, TEST_VOT);

        // Assert
        assertFalse(result);
    }

    @Test
    void isBreachingCiThresholdIfMitigated_ShouldReturnFalse_WhenScoreEqualsThreshold() {
        var ci1 = createCi("ciCode1");
        var ci2 = createCi("ciCode2");
        var cis = List.of(ci1, ci2);

        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        "ciCode1", new ContraIndicatorConfig("ciCode", 5, -5, "X"),
                        "ciCode2", new ContraIndicatorConfig("ciCode", 5, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // Act
        boolean result = cimitUtilityService.isBreachingCiThresholdIfMitigated(ci1, cis, TEST_VOT);

        // Assert
        assertFalse(result);
    }

    @ParameterizedTest
    @MethodSource("ciScoresAndUnsurpassedThresholds")
    void
            getMitigationEventIfBreachingOrActive_ShouldReturnEmpty_IfCiScoreNotBreachingAndNoExistingMitigations(
                    int ciScore1, int ciScore2, int ciScoreThreshold) throws ConfigException {
        // Arrange
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2"))
                .thenReturn(String.valueOf(ciScoreThreshold));

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, ciScore1, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, ciScore2, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("ci_1", ciConfig1);
        ciConfigMap.put("ci_2", ciConfig2);

        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var cis = List.of(createCi("ci_1"), createCi("ci_2"));

        // Act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // Assert
        assertTrue(
                result.isEmpty(),
                String.format(
                        "CIs with scores %s and %s should not breach threshold of %s",
                        ciScore1, ciScore2, ciScoreThreshold));
    }

    @Test
    void getMitigationEventIfBreachingOrActive_ShouldReturnMitigation_WhenCiCanBeMitigated()
            throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String document = "doc_type/213123";
        String documentType = "doc_type";
        var ci = createCi(code);
        ci.setDocument(document);
        var cis = List.of(ci);

        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of(journey), result);
    }

    @Test
    void
            getMitigationEventIfBreachingOrActive_ShouldReturnMitigation_WhenCiCanBeMitigatedWithNoDocInCi()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        var ci = createCi(code);
        var cis = List.of(ci);

        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, null))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of(journey), result);
    }

    @Test
    void
            getMitigationEventIfBreachingOrActive_ShouldReturnEmpty_IfCiIsMitigatableButDocTypeIsNotConfigured()
                    throws Exception {
        // Arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String ciDocumentIdentifier = "a-not-configured-doc-type";
        String configuredDocumentIdentifier = "a-configured-doc-type";
        var ci = createCi(code);
        ci.setDocument(ciDocumentIdentifier);
        var cis = List.of(ci);

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
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // Act
        Optional<String> result =
                cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // Assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void
            getMitigationEventIfBreachingOrActive_ShouldReturnEmpty_WhenBreachingAndCiIsNotMitigatable()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var ci = createCi(code);
        var cis = List.of(ci);

        when(mockConfigService.getCimitConfig()).thenReturn(Collections.emptyMap());
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void
            getMitigationEventIfBreachingOrActive_ShouldReturnMitigation_WhenNotBreachingAndCiIsAlreadyMitigated()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var ci = createCi(code);
        ci.setMitigation(List.of(new Mitigation()));
        var cis = List.of(ci);

        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute("some-event", null))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // assert
        assertEquals(Optional.of("some-event"), result);
    }

    @Test
    void
            getMitigationEventIfBreachingOrActive_ShouldReturnEmpty_WhenMitigationDoesNotResolveBreach()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var ci = createCi(code);
        var cis = List.of(ci);

        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute("journey", null))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -1, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void getCiMitigationEvent_ShouldReturnEmpty_WhenCiMitigationConfigNotFoundForDocType()
            throws Exception {
        // Arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        var ci = createCi(code);
        var cis = List.of(ci);

        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, "documentType"))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // Act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // Assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void
            getMitigationEventIfBreachingOrActive_ShouldReturnEmpty_WhenCiCanBeMitigatedButHasAlreadyMitigatedContraIndicator()
                    throws Exception {
        // arrange
        var code = "ci_code";
        var journey = "some_mitigation";
        String document = "doc_type/213123";
        String documentType = "doc_type";
        var ci = createCi(code);
        ci.setDocument(document);
        var mitCi = createCi("mit_ci_code");
        ci.setDocument(document);
        ci.setMitigation(List.of(new Mitigation()));
        var cis = List.of(ci, mitCi);

        when(mockConfigService.getCimitConfig())
                .thenReturn(Map.of(code, List.of(new MitigationRoute(journey, documentType))));
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(
                        code,
                        new ContraIndicatorConfig(code, 7, -5, "X"),
                        "mit_ci_code",
                        new ContraIndicatorConfig("mit_ci_code", 7, -5, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(cis, TEST_VOT);

        // assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void getContraIndicatorsReturnEmptyCIIfInvalidEvidenceWithNoCI() throws Exception {
        var contraIndicators =
                cimitUtilityService.getContraIndicatorsFromVc(
                        VerifiableCredential.fromValidJwt(
                                TEST_USER_ID,
                                null,
                                SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE)));

        assertTrue(contraIndicators.isEmpty());
    }

    @Test
    void getContraIndicatorsThrowsErrorIfNoEvidence() {
        assertThrows(
                CiExtractionException.class,
                () ->
                        cimitUtilityService.getContraIndicatorsFromVc(
                                VerifiableCredential.fromValidJwt(
                                        TEST_USER_ID,
                                        null,
                                        SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE))));
    }

    @Test
    void getContraIndicatorsFromVcReturnsNoCIsFromVcStringWhenNoCIs() throws Exception {
        // Act
        var cis =
                cimitUtilityService.getContraIndicatorsFromVc(
                        SIGNED_CIMIT_VC_NO_CI, "mock-user-id");

        // Assert
        assertTrue(cis.isEmpty());
    }

    @Test
    void getContraIndicatorsFromVcReturnsCIsFromVcStringIfPresent() throws Exception {
        // Act
        var cis =
                cimitUtilityService.getContraIndicatorsFromVc(
                        SIGNED_CONTRA_INDICATOR_VC_1, "mock-user-id");

        assertEquals(
                "[{\"code\":\"D01\",\"document\":\"passport/GBR/824159121\",\"incompleteMitigation\":[{\"code\":\"M02\",\"mitigatingCredential\":[{\"id\":\"urn:uuid:f5c9ff40-1dcd-4a8b-bf92-9456047c132f\",\"issuer\":\"https://another-credential-issuer.example/\",\"txn\":\"cdeef\",\"validFrom\":1663862090000}]}],\"issuanceDate\":1663689290000,\"issuers\":[\"https://issuing-cri.example\"],\"mitigation\":[{\"code\":\"M01\",\"mitigatingCredential\":[{\"id\":\"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"issuer\":\"https://credential-issuer.example/\",\"txn\":\"ghij\",\"validFrom\":1663775690000}]}],\"txn\":[\"abcdef\"]}]",
                OBJECT_MAPPER.writeValueAsString(cis));
    }

    @Test
    void getContraIndicatorsFromVcThrowsErrorIfVcHasNoEvidence() {
        // Act/Assert
        assertThrows(
                CiExtractionException.class,
                () ->
                        cimitUtilityService.getContraIndicatorsFromVc(
                                SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE, "mock-user-id"));
    }

    @Test
    void getContraIndicatorsFromVcThrowsErrorIfInvalidVc() {
        // Act/Assert
        assertThrows(
                CiExtractionException.class,
                () ->
                        cimitUtilityService.getContraIndicatorsFromVc(
                                VC_RESIDENCE_PERMIT_DCMAW, "mock-user-id"));
    }

    @Test
    void getMitigationEventIfBreachingOrActive_ReturnsEmpty_IfNoCis() throws Exception {
        // Arrange
        var code = "ci_code";
        Map<String, ContraIndicatorConfig> ciConfigMap =
                Map.of(code, new ContraIndicatorConfig(code, 4, -3, "X"));
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, TEST_VOT.name())).thenReturn("5");

        // act
        var result = cimitUtilityService.getMitigationEventIfBreachingOrActive(List.of(), TEST_VOT);

        // assert
        assertEquals(Optional.empty(), result);
    }

    private static ContraIndicator createCi(String code) {
        var ci = new ContraIndicator();
        ci.setCode(code);
        return ci;
    }

    private static ContraIndicator createCi(
            String code, Instant issuanceDate, List<Mitigation> mitigations, String document) {
        var ci = new ContraIndicator();
        ci.setCode(code);
        ci.setIssuanceDate(Date.from(issuanceDate));
        ci.setMitigation(mitigations);
        ci.setDocument(document);
        return ci;
    }
}
