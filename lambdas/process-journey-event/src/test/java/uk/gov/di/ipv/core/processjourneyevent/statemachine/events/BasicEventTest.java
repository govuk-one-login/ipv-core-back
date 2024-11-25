package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;

@ExtendWith(MockitoExtension.class)
class BasicEventTest {
    @Mock private ConfigService mockConfigService;
    @InjectMocks private JourneyContext journeyContext;

    @Test
    void resolveShouldReturnAState() throws Exception {
        var expectedResult = new TransitionResult(new BasicState(), null, null, null);
        BasicEvent basicEvent = new BasicEvent();
        basicEvent.setTargetStateObj(expectedResult.state());

        assertEquals(expectedResult, basicEvent.resolve(journeyContext));
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

        var result = basicEventWithCheckIfDisabledConfigured.resolve(journeyContext);

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

        var result = defaultEvent.resolve(journeyContext);

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

        var journeyContextWithName = new JourneyContext(mockConfigService, "test-context");
        var result = defaultEvent.resolve(journeyContextWithName);

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
}
