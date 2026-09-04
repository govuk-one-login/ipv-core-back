package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.collections.Merging.mergeLists;
import static uk.gov.di.ipv.core.library.collections.Merging.mergeMaps;

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

    // When entering a nested journey we need to keep any contexts or audit events from the outer
    // transition response
    public TransitionResult(TransitionResult result, TransitionResult outerResult) {
        this(
                result.state(),
                mergeLists(outerResult.auditEvents(), result.auditEvents()),
                mergeMaps(outerResult.auditContext(), result.auditContext()),
                result.targetEntryEvent(),
                mergeLists(outerResult.journeyContextsToSet(), result.journeyContextsToSet()),
                mergeLists(outerResult.journeyContextsToUnset(), result.journeyContextsToUnset()));
    }
}
