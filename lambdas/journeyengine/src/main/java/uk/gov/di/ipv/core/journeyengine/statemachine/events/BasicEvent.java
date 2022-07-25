package uk.gov.di.ipv.core.journeyengine.statemachine.events;

import uk.gov.di.ipv.core.journeyengine.statemachine.State;
import uk.gov.di.ipv.core.journeyengine.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.journeyengine.statemachine.responses.Context;
import uk.gov.di.ipv.core.journeyengine.statemachine.responses.JourneyStepResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class BasicEvent implements Event {

    private String name;
    private State targetState;
    private JourneyStepResponse response;

    public StateMachineResult resolve(Context context) {
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
