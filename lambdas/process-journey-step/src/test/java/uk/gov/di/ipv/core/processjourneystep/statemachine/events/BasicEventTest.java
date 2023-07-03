package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BasicEventTest {
    @Test
    void resolveShouldReturnAStateMachineResult() {
        State targetState = new State("TARGET_STATE");
        JourneyResponse journeyResponse = new JourneyResponse();

        BasicEvent basicEvent = new BasicEvent();
        basicEvent.setName("eventName");
        basicEvent.setTargetState(targetState);
        basicEvent.setResponse(journeyResponse);

        StateMachineResult result = basicEvent.resolve(JourneyContext.emptyContext());

        assertEquals(targetState, result.getState());
        assertEquals(journeyResponse, result.getJourneyStepResponse());
    }
}
