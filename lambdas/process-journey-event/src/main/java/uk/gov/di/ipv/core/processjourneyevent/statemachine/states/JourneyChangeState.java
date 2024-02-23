package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

@Data
@AllArgsConstructor
public class JourneyChangeState implements State {
    private IpvJourneyTypes journeyType;
    private String initialState;

    @Override
    public State transition(String eventName, String startState, JourneyContext journeyContext)
            throws UnknownEventException, UnknownStateException {
        throw new IllegalStateException("Cannot transition from JourneyChangeState");
    }
}
