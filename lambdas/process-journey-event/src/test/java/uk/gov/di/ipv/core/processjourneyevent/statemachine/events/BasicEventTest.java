package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class BasicEventTest {
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
