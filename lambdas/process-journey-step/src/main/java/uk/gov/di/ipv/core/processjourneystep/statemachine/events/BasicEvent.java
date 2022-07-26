package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyStepResponse;

@ExcludeFromGeneratedCoverageReport
public class BasicEvent implements Event {

    private String name;
    private State targetState;
    private JourneyStepResponse response;

    public StateMachineResult resolve(JourneyContext journeyContext) {
        return new StateMachineResult(targetState, response);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public State getTargetState() {
        return targetState;
    }

    public void setTargetState(State targetState) {
        this.targetState = targetState;
    }

    public JourneyStepResponse getResponse() {
        return response;
    }

    public void setResponse(JourneyStepResponse response) {
        this.response = response;
    }
}
