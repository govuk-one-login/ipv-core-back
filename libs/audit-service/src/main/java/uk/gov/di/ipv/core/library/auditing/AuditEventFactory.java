package uk.gov.di.ipv.core.library.auditing;

import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensions;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestricted;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;

public class AuditEventFactory {
    public AuditEvent createAuditEventWithDeviceInformation(
            AuditEventTypes eventName,
            String componentId,
            AuditEventUser user,
            AuditExtensions extensions,
            AuditRestrictedDeviceInformation restricted) {
        return new AuditEventWithDeviceInformation(
                eventName, componentId, user, extensions, restricted);
    }

    public AuditEvent createAuditEventWithoutDeviceInformation(
            AuditEventTypes eventName,
            String componentId,
            AuditEventUser user,
            AuditExtensions extensions,
            AuditRestricted restricted) {
        return new AuditEvent(eventName, componentId, user, extensions, restricted);
    }
}
