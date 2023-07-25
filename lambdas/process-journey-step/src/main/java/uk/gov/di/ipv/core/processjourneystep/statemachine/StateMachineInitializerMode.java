package uk.gov.di.ipv.core.processjourneystep.statemachine;

public enum StateMachineInitializerMode {
    STANDARD(""),
    TEST("test/");

    private final String pathPart;

    StateMachineInitializerMode(String pathPart) {
        this.pathPart = pathPart;
    }

    public String getPathPart() {
        return pathPart;
    }
}
