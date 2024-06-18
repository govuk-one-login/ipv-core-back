package uk.gov.di.ipv.core.library.auditing;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensions;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestricted;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedWithDeviceInformation;

import java.time.Instant;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditEvent {
    @JsonProperty private final long timestamp;

    @JsonProperty("event_timestamp_ms")
    private final long timestampMs;

    @JsonProperty("event_name")
    private final AuditEventTypes eventName;

    @JsonProperty
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final AuditExtensions extensions;

    @JsonProperty("component_id")
    private final String componentId;

    @JsonProperty private final AuditEventUser user;

    @JsonProperty
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final AuditRestricted restricted;

    @JsonCreator
    private AuditEvent(
            @JsonProperty(value = "event_name", required = true) AuditEventTypes eventName,
            @JsonProperty(value = "component_id", required = false) String componentId,
            @JsonProperty(value = "user", required = false) AuditEventUser user,
            @JsonProperty(value = "extensions", required = false) AuditExtensions extensions,
            @JsonProperty(value = "restricted", required = false) AuditRestricted restricted) {
        Instant now = Instant.now();
        this.timestamp = now.getEpochSecond();
        this.timestampMs = now.toEpochMilli();
        this.eventName = eventName;
        this.componentId = componentId;
        this.user = user;
        this.extensions = extensions;
        this.restricted = restricted;
    }

    public static AuditEvent createWithDeviceInformation(
            AuditEventTypes eventType,
            String componentId,
            AuditEventUser user,
            AuditExtensions extensions,
            AuditRestrictedWithDeviceInformation restricted) {
        return new AuditEvent(eventType, componentId, user, extensions, restricted);
    }

    public static AuditEvent createWithDeviceInformation(
            AuditEventTypes eventType,
            String componentId,
            AuditEventUser user,
            AuditRestrictedWithDeviceInformation restricted) {
        return new AuditEvent(eventType, componentId, user, null, restricted);
    }

    public static AuditEvent createWithoutDeviceInformation(
            AuditEventTypes eventType,
            String componentId,
            AuditEventUser user,
            AuditExtensions extensions,
            AuditRestricted restricted) {
        return new AuditEvent(eventType, componentId, user, extensions, restricted);
    }

    public static AuditEvent createWithoutDeviceInformation(
            AuditEventTypes eventType,
            String componentId,
            AuditEventUser user,
            AuditExtensions extensions) {
        return new AuditEvent(eventType, componentId, user, extensions, null);
    }

    public static AuditEvent createWithoutDeviceInformation(
            AuditEventTypes eventType, String componentId, AuditEventUser user) {
        return new AuditEvent(eventType, componentId, user, null, null);
    }
}
