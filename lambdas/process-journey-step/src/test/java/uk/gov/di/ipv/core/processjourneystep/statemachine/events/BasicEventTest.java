package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class BasicEventTest {
    @Mock private ConfigService mockConfigService;

    @Test
    void resolveShouldReturnAState() {
        BasicState targetState = new BasicState("TARGET_STATE");
        BasicEvent basicEvent = new BasicEvent(mockConfigService);
        basicEvent.setTargetStateObj(targetState);

        assertEquals(targetState, basicEvent.resolve(JourneyContext.emptyContext()));
    }

    @Test
    void resolveShouldReturnAlternativeStateIfACheckedCriIsDisabled() {
        BasicEvent basicEventWithCheckIfDisabledConfigured = new BasicEvent(mockConfigService);
        basicEventWithCheckIfDisabledConfigured.setTargetStateObj(new BasicState());

        BasicEvent alternativeEvent = new BasicEvent(mockConfigService);
        BasicState alternativeTargetState =
                new BasicState("THE_TARGET_STATE_FOR_THE_ALTERNATIVE_RESULT");
        alternativeEvent.setTargetStateObj(alternativeTargetState);

        when(mockConfigService.isEnabled("anEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("aDisabledCri")).thenReturn(false);
        LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
        checkIfDisabled.put("anEnabledCri", new BasicEvent(mockConfigService));
        checkIfDisabled.put("aDisabledCri", alternativeEvent);
        basicEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

        State resolve =
                basicEventWithCheckIfDisabledConfigured.resolve(JourneyContext.emptyContext());

        assertEquals(alternativeTargetState, resolve);
    }
}
