package uk.gov.di.ipv.core.processjourneystep.statemachine;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyStepResponse;

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
