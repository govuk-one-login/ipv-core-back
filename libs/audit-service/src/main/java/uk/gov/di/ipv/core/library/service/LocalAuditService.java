package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.exception.AuditException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

@ExcludeFromGeneratedCoverageReport
public class LocalAuditService implements AuditService {
    private static final Logger LOGGER = LogManager.getLogger();

    public static final ConcurrentLinkedDeque<AuditEvent> AUDIT_EVENTS =
            new ConcurrentLinkedDeque<>();

    private ConcurrentLinkedDeque<AuditEvent> pendingAuditEvents = new ConcurrentLinkedDeque<>();

    public static List<AuditEvent> getAuditEvents(String journeyId) {
        return AUDIT_EVENTS.stream()
                .filter(e -> e.getUser().getGovukSigninJourneyId().equals(journeyId))
                .toList();
    }

    @Override
    public void sendAuditEvent(AuditEvent auditEvent) throws AuditException {
        pendingAuditEvents.add(auditEvent);
        LOGGER.info(LogHelper.buildLogMessage("Sending audit event").with("event", auditEvent));
    }

    @Override
    public synchronized void awaitAuditEvents() {
        AUDIT_EVENTS.addAll(pendingAuditEvents);
        pendingAuditEvents = new ConcurrentLinkedDeque<>();
    }
}
