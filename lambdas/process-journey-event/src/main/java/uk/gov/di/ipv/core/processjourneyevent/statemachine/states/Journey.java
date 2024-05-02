package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import java.util.Map;

public record Journey(String name, String description, Map<String, State> states) {}
