package uk.gov.di.ipv.core.library.domain;

import lombok.Data;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

@Data
public class ContraIndicatorItem implements Comparable<ContraIndicatorItem> {
    private final String userId;
    private final String sortKey;
    private final String iss;
    private final String issuedAt;
    private final String ci;
    private final String ttl;

    @Override
    public int compareTo(ContraIndicatorItem other) {
        Instant thisInstant = Instant.from(DateTimeFormatter.ISO_INSTANT.parse(this.issuedAt));
        Instant otherInstant = Instant.from(DateTimeFormatter.ISO_INSTANT.parse(other.issuedAt));

        if (thisInstant.isAfter(otherInstant)) {
            return 1;
        } else if (this.equals(other)) {
            return 0;
        } else {
            return -1;
        }
    }
}
