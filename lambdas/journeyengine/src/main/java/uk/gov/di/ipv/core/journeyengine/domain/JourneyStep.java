package uk.gov.di.ipv.core.journeyengine.domain;

public enum JourneyStep {
    NEXT("next"),
    ERROR("error");

    private final String step;

    JourneyStep(String step) {
        this.step = step;
    }

    @Override
    public String toString() {
        return step;
    }
}
