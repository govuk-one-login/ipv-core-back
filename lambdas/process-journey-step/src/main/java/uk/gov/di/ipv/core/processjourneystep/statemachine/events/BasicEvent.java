package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyStepResponse;

@Data
public class BasicEvent implements Event {

    private String name;
    private State targetState;
    private JourneyStepResponse response;

    public StateMachineResult resolve(JourneyContext journeyContext) {
        return new StateMachineResult(targetState, response);
    }
}
