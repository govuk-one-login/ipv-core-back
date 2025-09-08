package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public record TransitionResult(
        State state,
        List<AuditEventTypes> auditEvents,
        Map<String, String> auditContext,
        String targetEntryEvent,
        List<String> journeyContextsToSet,
        List<String> journeyContextsToUnset) {
    public TransitionResult(State state) {
        this(state, List.of(), Map.of(), null, Collections.emptyList(), Collections.emptyList());
    }
}
