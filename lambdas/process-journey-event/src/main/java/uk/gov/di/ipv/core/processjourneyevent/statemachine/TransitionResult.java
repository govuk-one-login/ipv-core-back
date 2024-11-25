package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public record TransitionResult(
        State state,
        List<AuditEventTypes> auditEvents,
        Map<String, String> auditContext,
        String targetEntryEvent) {
    public TransitionResult(State state) {
        this(state, new ArrayList<>(), new HashMap<>(), null);
    }
}
