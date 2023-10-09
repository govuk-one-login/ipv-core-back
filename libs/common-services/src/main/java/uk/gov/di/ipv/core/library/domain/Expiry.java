package uk.gov.di.ipv.core.library.domain;

import java.time.Duration;
import java.time.Instant;

public class Expiry {
    public final String iso8061;

    public Expiry(String durationSecondsOrISO8061, Instant start) {
        iso8061 = start.plusSeconds(this.toSeconds(durationSecondsOrISO8061)).toString();
    }

    private long toSeconds(String durationSecondsOrISO8061) {
        try {
            return Long.parseLong(durationSecondsOrISO8061);
        } catch (NumberFormatException error) {
            return Duration.parse(durationSecondsOrISO8061).toSeconds();
        }
    }

    public long toEpochSeconds() {
        return Instant.parse(iso8061).getEpochSecond();
    }
}
