package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BasicEventTest {
    @Mock private ConfigService mockConfigService;
    @InjectMocks private JourneyContext journeyContext;

    @Test
    void resolveShouldReturnAState() throws Exception {
        BasicState targetState = new BasicState();
        BasicEvent basicEvent = new BasicEvent();
        basicEvent.setTargetStateObj(targetState);

        assertEquals(targetState, basicEvent.resolve(journeyContext));
    }

    @Test
    void resolveShouldReturnAlternativeStateIfACheckedCriIsDisabled() throws Exception {
        BasicEvent basicEventWithCheckIfDisabledConfigured = new BasicEvent();
        basicEventWithCheckIfDisabledConfigured.setTargetStateObj(new BasicState());

        BasicEvent alternativeEvent = new BasicEvent();
        BasicState alternativeTargetState = new BasicState();
        alternativeEvent.setTargetStateObj(alternativeTargetState);

        when(mockConfigService.isEnabled("anEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("aDisabledCri")).thenReturn(false);
        LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
        checkIfDisabled.put("anEnabledCri", new BasicEvent());
        checkIfDisabled.put("aDisabledCri", alternativeEvent);
        basicEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

        State resolve = basicEventWithCheckIfDisabledConfigured.resolve(journeyContext);

        assertEquals(alternativeTargetState, resolve);
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

        State resolve = defaultEvent.resolve(journeyContext);

        assertEquals(featureFlagTargetState, resolve);
    }

    @Test
    void initializeShouldSetAttributes() {
        BasicEvent basicEvent = new BasicEvent();
        BasicState targetStateObj = new BasicState();
        basicEvent.setTargetState("TARGET_STATE");

        BasicEvent checkIfDisabledEvent = new BasicEvent();
        checkIfDisabledEvent.setTargetState("CHECK_STATE");
        BasicState checkStateObj = new BasicState();

        basicEvent.setCheckIfDisabled(new LinkedHashMap<>(Map.of("aCriId", checkIfDisabledEvent)));

        basicEvent.initialize(
                "eventName",
                Map.of(
                        "TARGET_STATE", targetStateObj,
                        "CHECK_STATE", checkStateObj));

        assertEquals("eventName", basicEvent.getName());
        assertEquals(targetStateObj, basicEvent.getTargetStateObj());
        assertEquals(
                checkStateObj,
                ((BasicEvent) basicEvent.getCheckIfDisabled().get("aCriId")).getTargetStateObj());
    }
}
