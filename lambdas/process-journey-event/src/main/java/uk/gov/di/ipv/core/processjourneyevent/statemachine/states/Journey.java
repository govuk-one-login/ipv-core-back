package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import java.util.Map;

public record Journey(Map<String, State> states) {}
