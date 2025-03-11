package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.model.ContraIndicator;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_1;

@ExtendWith(MockitoExtension.class)
class BasicEventTest {
    @Mock private ConfigService mockConfigService;
    @Mock private CimitUtilityService mockCimitUtilityService;

    private EventResolveParameters eventResolveParameters;

    @BeforeEach
    void setUp() {
        eventResolveParameters =
                new EventResolveParameters(
                        "",
                        mockConfigService,
                        new IpvSessionItem(),
                        ClientOAuthSessionItem.builder().scope(ScopeConstants.OPENID).build(),
                        mockCimitUtilityService);
    }

    @Test
    void resolveShouldReturnAState() throws Exception {
        var expectedResult = new TransitionResult(new BasicState(), null, null, null);
        BasicEvent basicEvent = new BasicEvent();
        basicEvent.setTargetStateObj(expectedResult.state());

        assertEquals(expectedResult, basicEvent.resolve(eventResolveParameters));
    }

    @Test
    void resolveShouldReturnAlternativeStateIfACheckedCriIsDisabled() throws Exception {
        BasicEvent basicEventWithCheckIfDisabledConfigured = new BasicEvent();
        basicEventWithCheckIfDisabledConfigured.setTargetStateObj(new BasicState());

        BasicEvent alternativeEvent = new BasicEvent();
        BasicState alternativeTargetState = new BasicState();
        alternativeEvent.setTargetStateObj(alternativeTargetState);

        when(mockConfigService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, "anEnabledCri"))
                .thenReturn(true);
        when(mockConfigService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, "aDisabledCri"))
                .thenReturn(false);
        LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
        checkIfDisabled.put("anEnabledCri", new BasicEvent());
        checkIfDisabled.put("aDisabledCri", alternativeEvent);
        basicEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

        var result = basicEventWithCheckIfDisabledConfigured.resolve(eventResolveParameters);

        assertEquals(alternativeTargetState, result.state());
    }

    @Test
    void resolveShouldReturnAlternativeStateIfACheckedFeatureFlagIsSet() throws Exception {
        BasicEvent eventWithCheckFeatureFlagConfigured = new BasicEvent();
        BasicState featureFlagTargetState = new BasicState();
        eventWithCheckFeatureFlagConfigured.setTargetStateObj(featureFlagTargetState);

        BasicEvent defaultEvent = new BasicEvent();
        defaultEvent.setTargetStateObj(new BasicState());

        LinkedHashMap<String, Event> checkFeatureFlag = new LinkedHashMap<>();
        checkFeatureFlag.put(
                CoreFeatureFlag.UNUSED_PLACEHOLDER.getName(), eventWithCheckFeatureFlagConfigured);
        defaultEvent.setCheckFeatureFlag(checkFeatureFlag);

        var result = defaultEvent.resolve(eventResolveParameters);

        assertEquals(featureFlagTargetState, result.state());
    }

    @Test
    void resolveShouldReturnAlternativeStateIfJourneyContextIsSetAndIgnoreFeatureFlag()
            throws Exception {
        BasicEvent eventWithCheckFeatureFlagConfigured = new BasicEvent();
        BasicState featureFlagTargetState = new BasicState();
        eventWithCheckFeatureFlagConfigured.setTargetStateObj(featureFlagTargetState);

        BasicEvent eventWithContextConfigured = new BasicEvent();
        BasicState contextTargetState =
                new BasicState("evtWithContext", "", "test-context", null, null, null, null);
        eventWithContextConfigured.setTargetStateObj(contextTargetState);

        BasicEvent defaultEvent = new BasicEvent();
        defaultEvent.setTargetStateObj(
                new BasicState("defaultEvent", "", "", null, null, null, null));

        LinkedHashMap<String, Event> checkFeatureFlag = new LinkedHashMap<>();
        checkFeatureFlag.put(
                CoreFeatureFlag.UNUSED_PLACEHOLDER.getName(), eventWithCheckFeatureFlagConfigured);
        defaultEvent.setCheckFeatureFlag(checkFeatureFlag);

        LinkedHashMap<String, Event> checkContext = new LinkedHashMap<>();
        checkContext.put("test-context", eventWithContextConfigured);

        defaultEvent.setCheckJourneyContext(checkContext);

        var testParams =
                new EventResolveParameters(
                        "test-context",
                        mockConfigService,
                        null,
                        ClientOAuthSessionItem.builder().scope(ScopeConstants.OPENID).build(),
                        null);
        var result = defaultEvent.resolve(testParams);

        assertEquals(contextTargetState, result.state());
    }

    @Test
    void initializeShouldSetAttributes() {
        var basicEvent = new BasicEvent();
        var targetStateObj = new BasicState();
        basicEvent.setTargetState("TARGET_STATE");

        var checkIfDisabledEvent = new BasicEvent();
        checkIfDisabledEvent.setTargetState("CHECK_IF_DISABLED_STATE");
        var checkIfDisabledStateObj = new BasicState();

        var exitNestedJourneyEvent = new ExitNestedJourneyEvent();
        exitNestedJourneyEvent.setExitEventToEmit("getMetOut");
        var nestedJourneyExitEvent = new BasicEvent();

        var checkFeatureFlagEvent = new BasicEvent();
        checkFeatureFlagEvent.setTargetState("CHECK_FLAG_STATE");
        var checkFeatureFlagStateObj = new BasicState();

        var checkJourneyContextEvent = new BasicEvent();
        checkJourneyContextEvent.setTargetState("CHECK_CONTEXT_STATE");
        var checkJourneyContextStateObj = new BasicState();

        basicEvent.setCheckIfDisabled(
                new LinkedHashMap<>(
                        Map.of(
                                "aCriId",
                                checkIfDisabledEvent,
                                "exitEvent",
                                exitNestedJourneyEvent)));
        basicEvent.setCheckFeatureFlag(new LinkedHashMap<>(Map.of("aFlag", checkFeatureFlagEvent)));
        basicEvent.setCheckJourneyContext(
                new LinkedHashMap<>(Map.of("aContext", checkJourneyContextEvent)));

        basicEvent.initialize(
                "eventName",
                Map.of(
                        "TARGET_STATE", targetStateObj,
                        "CHECK_IF_DISABLED_STATE", checkIfDisabledStateObj,
                        "CHECK_FLAG_STATE", checkFeatureFlagStateObj,
                        "CHECK_CONTEXT_STATE", checkJourneyContextStateObj),
                Map.of("getMeOut", nestedJourneyExitEvent));

        assertEquals("eventName", basicEvent.getName());
        assertEquals(targetStateObj, basicEvent.getTargetStateObj());
        assertEquals(
                checkIfDisabledStateObj,
                ((BasicEvent) basicEvent.getCheckIfDisabled().get("aCriId")).getTargetStateObj());
        assertEquals(
                checkFeatureFlagStateObj,
                ((BasicEvent) basicEvent.getCheckFeatureFlag().get("aFlag")).getTargetStateObj());
        assertEquals(
                checkJourneyContextStateObj,
                ((BasicEvent) basicEvent.getCheckJourneyContext().get("aContext"))
                        .getTargetStateObj());
        assertEquals(
                nestedJourneyExitEvent,
                exitNestedJourneyEvent.getNestedJourneyExitEvents().get("getMeOut"));
    }

    @Nested
    class CheckMitigationConfigured {
        private List<ContraIndicator> testCis;
        private ClientOAuthSessionItem clientOAuthSessionItem;
        private IpvSessionItem ipvSessionItem;

        @BeforeEach
        void setUp() {
            testCis = List.of(new ContraIndicator());

            clientOAuthSessionItem =
                    ClientOAuthSessionItem.builder()
                            .userId("user-id")
                            .vtr(List.of(P2.name()))
                            .scope(ScopeConstants.OPENID)
                            .build();

            ipvSessionItem = new IpvSessionItem();
            ipvSessionItem.setSecurityCheckCredential(SIGNED_CONTRA_INDICATOR_VC_1);
        }

        @Test
        void
                resolveShouldReturnAlternativeStateIfMitigationJourneyIsFoundAndExistsInCheckMitigation()
                        throws Exception {
            // Arrange
            var basicEventWithCheckMitigationConfigured = new BasicEvent();

            var alternativeEvent = new BasicEvent();
            var alternativeTargetState = new BasicState();
            alternativeEvent.setTargetStateObj(alternativeTargetState);

            LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();
            checkMitigation.put("first-mitigation", alternativeEvent);

            basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

            when(mockCimitUtilityService.getContraIndicatorsFromVc(
                            SIGNED_CONTRA_INDICATOR_VC_1, clientOAuthSessionItem.getUserId()))
                    .thenReturn(testCis);
            when(mockCimitUtilityService.getMitigationJourneyEvent(eq(testCis), any()))
                    .thenReturn(Optional.of("first-mitigation"));

            // Act
            var result =
                    basicEventWithCheckMitigationConfigured.resolve(
                            new EventResolveParameters(
                                    "journeyContext",
                                    mockConfigService,
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    mockCimitUtilityService));

            // Assert
            assertEquals(alternativeTargetState, result.state());
        }

        @Test
        void
                resolveShouldReturnTargetStateIfMitigationJourneyIsFoundButDoesNotExistInCheckMitigation()
                        throws Exception {
            // Arrange
            var basicEventWithCheckMitigationConfigured = new BasicEvent();
            var originalTargetStateObj = new BasicState();
            basicEventWithCheckMitigationConfigured.setTargetStateObj(originalTargetStateObj);

            LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();
            checkMitigation.put("first-mitigation", new BasicEvent());
            basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

            when(mockCimitUtilityService.getContraIndicatorsFromVc(
                            SIGNED_CONTRA_INDICATOR_VC_1, clientOAuthSessionItem.getUserId()))
                    .thenReturn(testCis);
            when(mockCimitUtilityService.getMitigationJourneyEvent(eq(testCis), any()))
                    .thenReturn(Optional.of("mitigation-not-in-check-mitigation"));

            // Act
            var result =
                    basicEventWithCheckMitigationConfigured.resolve(
                            new EventResolveParameters(
                                    "journeyContext",
                                    mockConfigService,
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    mockCimitUtilityService));

            // Assert
            assertEquals(originalTargetStateObj, result.state());
        }

        @Test
        void resolveShouldReturnTargetStateIfNoValidMitigationFoundInSecurityCheckCredential()
                throws Exception {
            // Arrange
            var basicEventWithCheckMitigationConfigured = new BasicEvent();
            var originalTargetStateObj = new BasicState();
            basicEventWithCheckMitigationConfigured.setTargetStateObj(originalTargetStateObj);

            LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();

            checkMitigation.put("first-mitigation", new BasicEvent());

            basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

            when(mockCimitUtilityService.getContraIndicatorsFromVc(
                            SIGNED_CONTRA_INDICATOR_VC_1, clientOAuthSessionItem.getUserId()))
                    .thenReturn(List.of());
            when(mockCimitUtilityService.getMitigationJourneyEvent(eq(List.of()), any()))
                    .thenReturn(Optional.empty());

            // Act
            var result =
                    basicEventWithCheckMitigationConfigured.resolve(
                            new EventResolveParameters(
                                    "journeyContext",
                                    mockConfigService,
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    mockCimitUtilityService));

            // Assert
            assertEquals(originalTargetStateObj, result.state());
        }

        @Test
        void
                resolveReturnsOriginalTargetStateIfOnReverificationJourneyAndCheckMitigationIsConfigured()
                        throws Exception {
            var basicEventWithCheckMitigationConfigured = new BasicEvent();
            var originalTargetStateObj = new BasicState();
            basicEventWithCheckMitigationConfigured.setTargetStateObj(originalTargetStateObj);

            LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();

            checkMitigation.put("first-mitigation", new BasicEvent());

            basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

            // Act
            var result =
                    basicEventWithCheckMitigationConfigured.resolve(
                            new EventResolveParameters(
                                    "journeyContext",
                                    mockConfigService,
                                    ipvSessionItem,
                                    ClientOAuthSessionItem.builder()
                                            .scope(ScopeConstants.REVERIFICATION)
                                            .build(),
                                    mockCimitUtilityService));

            // Assert
            assertEquals(originalTargetStateObj, result.state());
            verify(mockCimitUtilityService, times(0)).getContraIndicatorsFromVc(any(), any());
        }

        @Test
        void resolveShouldThrowIfIpvSessionItemDoesNotContainSecurityCheckCredential() {
            // Arrange
            var basicEventWithCheckMitigationConfigured = new BasicEvent();
            LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();
            checkMitigation.put("first-mitigation", new BasicEvent());
            basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

            var ipvSessionWithMissingSecurityCheckCredential = new IpvSessionItem();

            // Act/Assert
            var exception =
                    assertThrows(
                            JourneyEngineException.class,
                            () ->
                                    basicEventWithCheckMitigationConfigured.resolve(
                                            new EventResolveParameters(
                                                    "journeyContext",
                                                    mockConfigService,
                                                    ipvSessionWithMissingSecurityCheckCredential,
                                                    clientOAuthSessionItem,
                                                    mockCimitUtilityService)));

            assertEquals("Missing security check credential", exception.getCause().getMessage());
        }
    }
}
