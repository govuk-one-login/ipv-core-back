package uk.gov.di.ipv.core.journeyengine.statemachine;

public enum JourneyStep {
    NEXT("next"),
    ERROR("error"),
    FAIL("fail");

    private final String step;

    JourneyStep(String step) {
        this.step = step;
    }

    @Override
    public String toString() {
        return step;
    }
}
