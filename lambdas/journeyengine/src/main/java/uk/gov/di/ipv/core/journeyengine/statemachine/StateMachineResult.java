package uk.gov.di.ipv.core.journeyengine.statemachine;

import uk.gov.di.ipv.core.journeyengine.statemachine.responses.JourneyStepResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class StateMachineResult {

    private final State state;
    private final JourneyStepResponse journeyStepResponse;

    public StateMachineResult(State state, JourneyStepResponse journeyStepResponse) {
        this.state = state;
        this.journeyStepResponse = journeyStepResponse;
    }

    public State getState() {
        return state;
    }

    public JourneyStepResponse getJourneyStepResponse() {
        return journeyStepResponse;
    }
}
