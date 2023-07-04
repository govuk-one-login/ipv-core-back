package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class BasicEventTest {
    @SystemStub private static EnvironmentVariables environmentVariables;

    @BeforeAll
    static void beforeAll() {
        environmentVariables.set("IS_LOCAL", "true");
    }

    @Test
    void resolveShouldReturnAState() {
        BasicEvent event = new BasicEvent();
        State targetState = new State();
        event.setTargetStateObj(targetState);
        assertEquals(targetState, event.resolve(JourneyContext.emptyContext()));
    }

    @Test
    void resolveShouldReturnAlternativeStateIfACheckedCriIsDisabled() {
        ConfigService mockConfigService = mock(ConfigService.class);
        when(mockConfigService.isEnabled("aCriId")).thenReturn(false);

        BasicEvent eventWithCheckIfDisabled = new BasicEvent(mockConfigService);

        State alternativeState = new State();
        BasicEvent alternativeEvent = new BasicEvent();
        alternativeEvent.setTargetStateObj(alternativeState);

        eventWithCheckIfDisabled.setCheckIfDisabled(
                new LinkedHashMap<>(Map.of("aCriId", alternativeEvent)));

        assertEquals(
                alternativeState, eventWithCheckIfDisabled.resolve(JourneyContext.emptyContext()));
    }

    @Test
    void resolveShouldReturnFirstAlternativeStateIfMultipleCheckedCrisAreDisabled() {
        ConfigService mockConfigService = mock(ConfigService.class);
        when(mockConfigService.isEnabled("enabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("firstDisabledCri")).thenReturn(false);

        BasicEvent eventWithCheckIfDisabled = new BasicEvent(mockConfigService);

        State firstAlternativeState = new State();
        State secondAlternativeState = new State();
        State thirdAlternativeState = new State();

        BasicEvent firstAlternativeEvent = new BasicEvent();
        BasicEvent secondAlternativeEvent = new BasicEvent();
        BasicEvent thirdAlternativeEvent = new BasicEvent();

        firstAlternativeEvent.setTargetStateObj(firstAlternativeState);
        secondAlternativeEvent.setTargetStateObj(secondAlternativeState);
        thirdAlternativeEvent.setTargetStateObj(thirdAlternativeState);

        LinkedHashMap<String, Event> linkedHashMap = new LinkedHashMap<>();
        linkedHashMap.put("enabledCri", firstAlternativeEvent);
        linkedHashMap.put("firstDisabledCri", secondAlternativeEvent);
        linkedHashMap.put("secondDisabledCri", thirdAlternativeEvent);

        eventWithCheckIfDisabled.setCheckIfDisabled(linkedHashMap);
        assertEquals(
                secondAlternativeState,
                eventWithCheckIfDisabled.resolve(JourneyContext.emptyContext()));
    }

    @Test
    void resolveShouldReturnTargetStateIfAllCheckedCrisAreEnabled() {
        ConfigService mockConfigService = mock(ConfigService.class);
        when(mockConfigService.isEnabled("enabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("secondEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("thirdEnabledCri")).thenReturn(true);

        State targetState = new State();
        BasicEvent eventWithCheckIfDisabled = new BasicEvent(mockConfigService);
        eventWithCheckIfDisabled.setTargetStateObj(targetState);

        BasicEvent alternativeEvent = new BasicEvent();

        LinkedHashMap<String, Event> aCriId =
                new LinkedHashMap<>(
                        Map.of(
                                "enabledCri", alternativeEvent,
                                "secondEnabledCri", alternativeEvent,
                                "thirdEnabledCri", alternativeEvent));
        eventWithCheckIfDisabled.setCheckIfDisabled(aCriId);

        assertEquals(targetState, eventWithCheckIfDisabled.resolve(JourneyContext.emptyContext()));
    }

    @Test
    void bootstrapShouldSetFields() {
        BasicEvent basicEvent = new BasicEvent();
        basicEvent.setTargetState("TARGET_STATE");

        BasicEvent checkIfDisabledEvent = new BasicEvent();
        checkIfDisabledEvent.setTargetState("CHECK_IF_DISABLED_TARGET_STATE");

        basicEvent.setCheckIfDisabled(new LinkedHashMap<>(Map.of("next", checkIfDisabledEvent)));

        State targetState = new State();
        State checkIfDisabledTargetState = new State();

        Map<String, State> statesMap =
                Map.of(
                        "TARGET_STATE", targetState,
                        "CHECK_IF_DISABLED_TARGET_STATE", checkIfDisabledTargetState);

        basicEvent.bootstrap("eventName", statesMap);

        assertEquals("eventName", basicEvent.getName());
        assertEquals(targetState, basicEvent.getTargetStateObj());
        assertEquals(checkIfDisabledTargetState, checkIfDisabledEvent.getTargetStateObj());
    }
}
