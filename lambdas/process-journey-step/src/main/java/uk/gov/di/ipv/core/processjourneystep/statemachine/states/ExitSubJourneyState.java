package uk.gov.di.ipv.core.processjourneystep.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ExitSubJourneyState implements State {
    private String exitEvent;
    private String name;

    public ExitSubJourneyState(String name) {
        this.name = name;
    }

    @Override
    public State transition(String eventName, String startState, JourneyContext journeyContext)
            throws UnknownEventException {
        return null;
    }

    @Override
    public String toString() {
        return this.name;
    }
}
