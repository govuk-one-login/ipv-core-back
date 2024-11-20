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

    public static List<AuditEventTypes> mergeAuditEvents(
            List<AuditEventTypes> left, List<AuditEventTypes> right) {
        if (left == null && right == null) {
            return new ArrayList<>();
        }
        if (left == null) {
            return right;
        }
        if (right == null) {
            return left;
        }
        var merged = new ArrayList<AuditEventTypes>();
        merged.addAll(left);
        merged.addAll(right);
        return merged;
    }

    public static Map<String, String> mergeAuditContexts(
            Map<String, String> left, Map<String, String> right) {
        if (left == null && right == null) {
            return new HashMap<>();
        }
        if (left == null) {
            return right;
        }
        if (right == null) {
            return left;
        }
        var merged = new HashMap<String, String>();
        merged.putAll(left);
        merged.putAll(right);
        return merged;
    }
}
