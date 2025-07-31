package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.exception.AuditException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

@ExcludeFromGeneratedCoverageReport
public class LocalAuditService implements AuditService {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final Deque<AuditEvent> AUDIT_EVENTS = new ConcurrentLinkedDeque<>();

    private final Deque<AuditEvent> pendingAuditEvents = new ConcurrentLinkedDeque<>();

    public static List<AuditEvent> getAuditEvents(String userId) {
        return AUDIT_EVENTS.stream()
                .filter(
                        event ->
                                event.getUser() != null
                                        && userId.equals(event.getUser().getUserId()))
                .toList();
    }

    @Override
    public void sendAuditEvent(AuditEvent auditEvent) throws AuditException {
        pendingAuditEvents.addLast(auditEvent);
        LOGGER.info(
                LogHelper.buildLogMessage("Sending audit event")
                        .with("event", auditEvent.getEventName()));
    }

    @Override
    public void awaitAuditEvents() {
        var next = pendingAuditEvents.pollFirst();
        while (next != null) {
            AUDIT_EVENTS.addLast(next);
            next = pendingAuditEvents.pollFirst();
        }
    }
}
