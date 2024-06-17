package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensions;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;

public class AuditEventWithDeviceInformation extends AuditEvent {

    @JsonCreator
    public AuditEventWithDeviceInformation(
            @JsonProperty(value = "event_name", required = true) AuditEventTypes eventName,
            @JsonProperty(value = "component_id", required = false) String componentId,
            @JsonProperty(value = "user", required = false) AuditEventUser user,
            @JsonProperty(value = "extensions", required = false) AuditExtensions extensions,
            @JsonProperty(value = "restricted", required = true)
                    AuditRestrictedDeviceInformation restricted) {
        super(eventName, componentId, user, extensions, restricted);
    }
}
