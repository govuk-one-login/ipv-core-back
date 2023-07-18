package uk.gov.di.ipv.core.processjourneystep.statemachine.states;

import lombok.Data;

import java.util.Map;

@Data
public class SubJourneyDefinition {
    private Map<String, State> subJourneyStates;
}
