package uk.gov.di.ipv.core.processjourneystep.statemachine;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class StateTest {

    public static final State CURRENT_STATE = new State("CURRENT_STATE");
    private static final State TARGET_STATE = new State("TARGET_STATE");
    private static final JourneyResponse JOURNEY_RESPONSE = new JourneyResponse("stepId");
    private static final BasicEvent CURRENT_TO_TARGET_EVENT = new BasicEvent();
    ;

    @BeforeAll
    private static void beforeAll() {
        CURRENT_TO_TARGET_EVENT.setName("eventName");
        CURRENT_TO_TARGET_EVENT.setTargetState(TARGET_STATE);
        CURRENT_TO_TARGET_EVENT.setResponse(JOURNEY_RESPONSE);
        CURRENT_STATE.setEvents(Map.of("next", CURRENT_TO_TARGET_EVENT));
    }

    @Test
    void transitionShouldReturnAStateMachineResult() throws Exception {
        StateMachineResult stateMachineResult =
                CURRENT_STATE.transition("next", JourneyContext.emptyContext());

        assertEquals(TARGET_STATE, stateMachineResult.getState());
    }

    @Test
    void transitionShouldThrowIfEventNotFound() {
        assertThrows(
                UnknownEventException.class,
                () -> CURRENT_STATE.transition("unknown-event", JourneyContext.emptyContext()));
    }
}
