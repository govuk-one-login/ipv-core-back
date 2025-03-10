package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;

@Data
@AllArgsConstructor
public class JourneyChangeState implements State {
    private IpvJourneyTypes journeyType;
    private String initialState;

    @Override
    public TransitionResult transition(
            String eventName, String startState, EventResolveParameters eventResolveParameters)
            throws UnknownEventException, UnknownStateException {
        throw new IllegalStateException("Cannot transition from JourneyChangeState");
    }
}
