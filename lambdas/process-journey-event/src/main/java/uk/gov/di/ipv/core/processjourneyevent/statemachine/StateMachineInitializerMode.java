package uk.gov.di.ipv.core.processjourneyevent.statemachine;

public enum StateMachineInitializerMode {
    STANDARD("journey-maps/"),
    TEST("test/");

    private final String pathPart;

    StateMachineInitializerMode(String pathPart) {
        this.pathPart = pathPart;
    }

    public String getPathPart() {
        return pathPart;
    }
}
