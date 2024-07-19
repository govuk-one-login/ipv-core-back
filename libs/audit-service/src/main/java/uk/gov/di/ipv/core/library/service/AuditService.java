package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.exception.AuditException;

public interface AuditService {
    static AuditService create(ConfigService configService) {
        return new SqsAuditService(SqsAuditService.getSqsClient(), configService);
    }

    void sendAuditEvent(AuditEvent auditEvent) throws AuditException;

    void awaitAuditEvents();
}
