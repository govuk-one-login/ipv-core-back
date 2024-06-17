package uk.gov.di.ipv.core.library.auditing.restricted;

public interface AuditRestrictedWithDeviceInformation extends AuditRestricted {
    DeviceInformation deviceInformation();
}
