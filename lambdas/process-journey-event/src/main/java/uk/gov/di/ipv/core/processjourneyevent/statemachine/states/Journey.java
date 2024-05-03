package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record Journey(Map<String, State> states) {}
