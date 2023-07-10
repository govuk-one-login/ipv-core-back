package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.PageResponse;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class BasicEventTest {
    @Mock private ConfigService mockConfigService;

    @Test
    void resolveShouldReturnAStateMachineResult() {
        State targetState = new State("TARGET_STATE");
        JourneyResponse journeyResponse = new JourneyResponse();

        BasicEvent basicEvent = new BasicEvent(mockConfigService);
        basicEvent.setName("eventName");
        basicEvent.setTargetState(targetState);
        basicEvent.setResponse(journeyResponse);

        StateMachineResult result = basicEvent.resolve(JourneyContext.emptyContext());

        assertEquals(targetState, result.getState());
        assertEquals(journeyResponse, result.getJourneyStepResponse());
    }

    @Test
    void resolveShouldReturnAlternativeResultIfACheckedCriIsDisabled() {
        BasicEvent basicEventWithCheckIfDisabledConfigured = new BasicEvent(mockConfigService);
        basicEventWithCheckIfDisabledConfigured.setName("eventName");
        basicEventWithCheckIfDisabledConfigured.setTargetState(new State());
        basicEventWithCheckIfDisabledConfigured.setResponse(new PageResponse());

        BasicEvent alternativeEvent = new BasicEvent(mockConfigService);
        State alternativeState = new State("THE_TARGET_STATE_FOR_THE_ALTERNATIVE_RESULT");
        PageResponse alternativePageResponse = new PageResponse();
        alternativePageResponse.setPageId("alternativePageId");
        alternativeEvent.setTargetState(alternativeState);
        alternativeEvent.setResponse(alternativePageResponse);

        when(mockConfigService.isEnabled("anEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("aDisabledCri")).thenReturn(false);
        LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
        checkIfDisabled.put("anEnabledCri", new BasicEvent(mockConfigService));
        checkIfDisabled.put("aDisabledCri", alternativeEvent);
        basicEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

        StateMachineResult result =
                basicEventWithCheckIfDisabledConfigured.resolve(JourneyContext.emptyContext());

        assertEquals(alternativeState, result.getState());
        assertEquals(
                "alternativePageId",
                result.getJourneyStepResponse().value(mockConfigService).get("page"));
    }
}
