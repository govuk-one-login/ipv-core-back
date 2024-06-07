package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.CriStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.ProcessStepResponse;

import java.io.IOException;
import java.util.Map;

public class StateMachine {
    public static final String DELIMITER = "/";
    private static final String ATTEMPT_RECOVERY_EVENT = "attempt-recovery";

    private final Map<String, State> states;

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public TransitionResult transition(
            String startState, String event, JourneyContext journeyContext, String currentPage)
            throws UnknownEventException, UnknownStateException {
        var state = states.get(startState.split(DELIMITER)[0]);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        // Check page event is allowed
        if (currentPage != null && state instanceof BasicState basicState) {
            if (isPageOrCriStateAndOutOfSync(basicState, currentPage)) {
                return new TransitionResult(state);
            } else if (basicState.getResponse() instanceof ProcessStepResponse) {
                throw new UnknownStateException(
                        String.format(
                                "Unexpected page event (%s) from page (%s) received in process state (%s)",
                                event, currentPage, startState));
            }
        }

        // Special recovery event
        if (ATTEMPT_RECOVERY_EVENT.equals(event)) {
            return new TransitionResult(state);
        }

        var result = state.transition(event, startState, journeyContext);

        // Resolve nested journey
        if (result.state() instanceof NestedJourneyInvokeState) {
            return result.state().transition(event, startState, journeyContext);
        }

        return result;
    }

    private boolean isPageOrCriStateAndOutOfSync(BasicState basicState, String currentPage) {
        return basicState.getResponse() instanceof PageStepResponse pageStepResponse
                        && !pageStepResponse.getPageId().equals(currentPage)
                || basicState.getResponse() instanceof CriStepResponse;
    }
}
